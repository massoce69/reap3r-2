// ─────────────────────────────────────────────
// MASSVISION Reap3r — Alerting Service
// ─────────────────────────────────────────────
import { query, transaction } from '../db/pool.js';

// ════════════════════════════════════════════
// ALERT RULES
// ════════════════════════════════════════════

export async function createAlertRule(orgId: string, userId: string, data: {
  name: string; description?: string; rule_type: string;
  scope_type?: string; scope_value?: string;
  params?: Record<string, any>; severity?: string;
  cooldown_sec?: number; is_enabled?: boolean;
  escalations?: Array<{
    step: number; delay_sec: number; target_type: string;
    target_id?: string; target_role?: string; channels: string[];
  }>;
}) {
  return transaction(async (client) => {
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO alert_rules (org_id, name, description, rule_type, scope_type, scope_value, params, severity, cooldown_sec, is_enabled, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [orgId, data.name, data.description ?? null, data.rule_type,
       data.scope_type ?? 'all', data.scope_value ?? null,
       JSON.stringify(data.params ?? {}), data.severity ?? 'high',
       data.cooldown_sec ?? 300, data.is_enabled ?? true, userId]
    );
    const rule = rows[0];

    if (data.escalations?.length) {
      for (const esc of data.escalations) {
        await client.query(
          `INSERT INTO alert_escalations (rule_id, step, delay_sec, target_type, target_id, target_role, channels)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [rule.id, esc.step, esc.delay_sec, esc.target_type,
           esc.target_id ?? null, esc.target_role ?? null, JSON.stringify(esc.channels)]
        );
      }
    }

    return rule;
  });
}

export async function updateAlertRule(orgId: string, ruleId: string, data: {
  name?: string; description?: string; params?: Record<string, any>;
  severity?: string; cooldown_sec?: number; is_enabled?: boolean;
  scope_type?: string; scope_value?: string;
  escalations?: Array<{
    step: number; delay_sec: number; target_type: string;
    target_id?: string; target_role?: string; channels: string[];
  }>;
}) {
  return transaction(async (client) => {
    const sets: string[] = [];
    const vals: any[] = [];
    let idx = 1;

    const addField = (col: string, val: any) => {
      if (val !== undefined) { sets.push(`${col} = $${idx++}`); vals.push(val); }
    };
    addField('name', data.name);
    addField('description', data.description);
    addField('params', data.params ? JSON.stringify(data.params) : undefined);
    addField('severity', data.severity);
    addField('cooldown_sec', data.cooldown_sec);
    addField('is_enabled', data.is_enabled);
    addField('scope_type', data.scope_type);
    addField('scope_value', data.scope_value);
    sets.push(`updated_at = NOW()`);

    vals.push(orgId, ruleId);
    const { rowCount } = await client.query(
      `UPDATE alert_rules SET ${sets.join(', ')} WHERE org_id = $${idx++} AND id = $${idx++}`,
      vals
    );
    if (!rowCount) return null;

    // Replace escalations if provided
    if (data.escalations) {
      await client.query('DELETE FROM alert_escalations WHERE rule_id = $1', [ruleId]);
      for (const esc of data.escalations) {
        await client.query(
          `INSERT INTO alert_escalations (rule_id, step, delay_sec, target_type, target_id, target_role, channels)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [ruleId, esc.step, esc.delay_sec, esc.target_type,
           esc.target_id ?? null, esc.target_role ?? null, JSON.stringify(esc.channels)]
        );
      }
    }

    return getRuleById(orgId, ruleId);
  });
}

export async function deleteAlertRule(orgId: string, ruleId: string) {
  const { rowCount } = await query(
    'DELETE FROM alert_rules WHERE org_id = $1 AND id = $2', [orgId, ruleId]
  );
  return (rowCount ?? 0) > 0;
}

export async function listAlertRules(orgId: string, opts: {
  page?: number; limit?: number; rule_type?: string; is_enabled?: boolean;
}) {
  const page = opts.page ?? 1;
  const limit = opts.limit ?? 25;
  const offset = (page - 1) * limit;
  const wheres = ['org_id = $1'];
  const params: any[] = [orgId];
  let idx = 2;

  if (opts.rule_type) { wheres.push(`rule_type = $${idx++}`); params.push(opts.rule_type); }
  if (opts.is_enabled !== undefined) { wheres.push(`is_enabled = $${idx++}`); params.push(opts.is_enabled); }

  const where = wheres.join(' AND ');
  const [countRes, dataRes] = await Promise.all([
    query(`SELECT COUNT(*) FROM alert_rules WHERE ${where}`, params),
    query(`SELECT * FROM alert_rules WHERE ${where} ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
      [...params, limit, offset]),
  ]);

  // Attach escalations
  const rules = dataRes.rows;
  if (rules.length) {
    const ruleIds = rules.map(r => r.id);
    const escRes = await query(
      `SELECT * FROM alert_escalations WHERE rule_id = ANY($1) ORDER BY step`, [ruleIds]
    );
    const escMap = new Map<string, any[]>();
    for (const e of escRes.rows) {
      if (!escMap.has(e.rule_id)) escMap.set(e.rule_id, []);
      escMap.get(e.rule_id)!.push(e);
    }
    for (const r of rules) {
      r.escalations = escMap.get(r.id) ?? [];
    }
  }

  return { data: rules, total: parseInt(countRes.rows[0].count), page, limit };
}

export async function getRuleById(orgId: string, ruleId: string) {
  const { rows } = await query('SELECT * FROM alert_rules WHERE org_id = $1 AND id = $2', [orgId, ruleId]);
  if (!rows[0]) return null;
  const escRes = await query('SELECT * FROM alert_escalations WHERE rule_id = $1 ORDER BY step', [ruleId]);
  rows[0].escalations = escRes.rows;
  return rows[0];
}

// ════════════════════════════════════════════
// ALERT EVENTS
// ════════════════════════════════════════════

export async function createAlertEvent(data: {
  org_id: string; rule_id?: string; rule_name?: string;
  entity_type: string; entity_id?: string;
  fingerprint: string; severity: string;
  title: string; details?: Record<string, any>;
}) {
  // Dedup: check if open/ack event with same fingerprint exists
  const existing = await query(
    `SELECT id FROM alert_events WHERE org_id = $1 AND fingerprint = $2 AND status IN ('open','acknowledged') LIMIT 1`,
    [data.org_id, data.fingerprint]
  );
  if (existing.rows.length > 0) {
    // Update existing — bump updated_at
    await query('UPDATE alert_events SET updated_at = NOW() WHERE id = $1', [existing.rows[0].id]);
    return { id: existing.rows[0].id, deduplicated: true };
  }

  const { rows } = await query<{ id: string }>(
    `INSERT INTO alert_events (org_id, rule_id, rule_name, entity_type, entity_id, fingerprint, severity, status, title, details)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'open',$8,$9) RETURNING id`,
    [data.org_id, data.rule_id ?? null, data.rule_name ?? null,
     data.entity_type, data.entity_id ?? null,
     data.fingerprint, data.severity, data.title,
     JSON.stringify(data.details ?? {})]
  );
  return { id: rows[0].id, deduplicated: false };
}

export async function listAlertEvents(orgId: string, opts: {
  page?: number; limit?: number; status?: string; severity?: string;
  company_id?: string; folder_id?: string; entity_type?: string;
  rule_type?: string;
}) {
  const page = opts.page ?? 1;
  const limit = opts.limit ?? 25;
  const offset = (page - 1) * limit;
  const wheres = ['e.org_id = $1'];
  const params: any[] = [orgId];
  let idx = 2;

  if (opts.status) { wheres.push(`e.status = $${idx++}`); params.push(opts.status); }
  if (opts.severity) { wheres.push(`e.severity = $${idx++}`); params.push(opts.severity); }
  if (opts.entity_type) { wheres.push(`e.entity_type = $${idx++}`); params.push(opts.entity_type); }

  const where = wheres.join(' AND ');
  const [countRes, dataRes] = await Promise.all([
    query(`SELECT COUNT(*) FROM alert_events e WHERE ${where}`, params),
    query(
      `SELECT e.*, r.rule_type
       FROM alert_events e
       LEFT JOIN alert_rules r ON r.id = e.rule_id
       WHERE ${where}
       ORDER BY e.created_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
      [...params, limit, offset]
    ),
  ]);

  return { data: dataRes.rows, total: parseInt(countRes.rows[0].count), page, limit };
}

export async function getAlertEventById(orgId: string, eventId: string) {
  const { rows } = await query(
    `SELECT e.*, r.rule_type
     FROM alert_events e LEFT JOIN alert_rules r ON r.id = e.rule_id
     WHERE e.org_id = $1 AND e.id = $2`,
    [orgId, eventId]
  );
  if (!rows[0]) return null;

  // Load acks
  const ackRes = await query(
    `SELECT a.*, u.email AS user_email FROM alert_acks a
     JOIN users u ON u.id = a.user_id
     WHERE a.event_id = $1 ORDER BY a.created_at`,
    [eventId]
  );
  rows[0].acks = ackRes.rows;

  // Load notifications
  const notifRes = await query(
    'SELECT * FROM alert_notifications WHERE event_id = $1 ORDER BY created_at',
    [eventId]
  );
  rows[0].notifications = notifRes.rows;

  return rows[0];
}

export async function ackAlertEvent(orgId: string, eventId: string, userId: string, note?: string) {
  const { rowCount } = await query(
    `UPDATE alert_events SET status = 'acknowledged', updated_at = NOW()
     WHERE org_id = $1 AND id = $2 AND status = 'open'`,
    [orgId, eventId]
  );
  if (!rowCount) return false;
  await query(
    `INSERT INTO alert_acks (event_id, user_id, action, note) VALUES ($1,$2,'ack',$3)`,
    [eventId, userId, note ?? null]
  );
  return true;
}

export async function resolveAlertEvent(orgId: string, eventId: string, userId: string, note?: string) {
  const { rowCount } = await query(
    `UPDATE alert_events SET status = 'resolved', resolved_at = NOW(), resolved_by = $3, updated_at = NOW()
     WHERE org_id = $1 AND id = $2 AND status IN ('open','acknowledged')`,
    [orgId, eventId, userId]
  );
  if (!rowCount) return false;
  await query(
    `INSERT INTO alert_acks (event_id, user_id, action, note) VALUES ($1,$2,'resolve',$3)`,
    [eventId, userId, note ?? null]
  );
  return true;
}

export async function snoozeAlertEvent(orgId: string, eventId: string, userId: string, durationMin: number, note?: string) {
  const snoozedUntil = new Date(Date.now() + durationMin * 60 * 1000).toISOString();
  const { rowCount } = await query(
    `UPDATE alert_events SET status = 'snoozed', snoozed_until = $3, updated_at = NOW()
     WHERE org_id = $1 AND id = $2 AND status IN ('open','acknowledged')`,
    [orgId, eventId, snoozedUntil]
  );
  if (!rowCount) return false;
  await query(
    `INSERT INTO alert_acks (event_id, user_id, action, note, snooze_min) VALUES ($1,$2,'snooze',$3,$4)`,
    [eventId, userId, note ?? null, durationMin]
  );
  return true;
}

// Re-open snoozed events whose snooze period has expired
export async function reopenExpiredSnoozes() {
  const { rowCount } = await query(
    `UPDATE alert_events SET status = 'open', snoozed_until = NULL, updated_at = NOW()
     WHERE status = 'snoozed' AND snoozed_until <= NOW()`
  );
  return rowCount ?? 0;
}

// ════════════════════════════════════════════
// ALERT STATS
// ════════════════════════════════════════════

export async function getAlertStats(orgId: string) {
  const { rows } = await query(
    `SELECT
       COUNT(*) FILTER (WHERE status = 'open') AS open_count,
       COUNT(*) FILTER (WHERE status = 'acknowledged') AS ack_count,
       COUNT(*) FILTER (WHERE status = 'snoozed') AS snoozed_count,
       COUNT(*) FILTER (WHERE status = 'resolved' AND resolved_at >= NOW() - INTERVAL '24 hours') AS resolved_24h,
       COUNT(*) FILTER (WHERE severity = 'critical' AND status IN ('open','acknowledged')) AS critical_open
     FROM alert_events WHERE org_id = $1`,
    [orgId]
  );
  return rows[0];
}

// ════════════════════════════════════════════
// INTEGRATIONS
// ════════════════════════════════════════════

export async function listIntegrations(orgId: string) {
  const { rows } = await query(
    'SELECT * FROM alert_integrations WHERE org_id = $1 ORDER BY created_at', [orgId]
  );
  return { data: rows };
}

export async function createIntegration(orgId: string, data: {
  type: string; name: string; config: Record<string, any>; is_enabled?: boolean;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO alert_integrations (org_id, type, name, config, is_enabled)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [orgId, data.type, data.name, JSON.stringify(data.config), data.is_enabled ?? true]
  );
  return rows[0];
}

export async function updateIntegration(orgId: string, id: string, data: {
  name?: string; config?: Record<string, any>; is_enabled?: boolean;
}) {
  const sets: string[] = [];
  const vals: any[] = [];
  let idx = 1;
  if (data.name !== undefined) { sets.push(`name = $${idx++}`); vals.push(data.name); }
  if (data.config !== undefined) { sets.push(`config = $${idx++}`); vals.push(JSON.stringify(data.config)); }
  if (data.is_enabled !== undefined) { sets.push(`is_enabled = $${idx++}`); vals.push(data.is_enabled); }
  sets.push('updated_at = NOW()');
  vals.push(orgId, id);
  const { rowCount } = await query(
    `UPDATE alert_integrations SET ${sets.join(', ')} WHERE org_id = $${idx++} AND id = $${idx++}`, vals
  );
  return (rowCount ?? 0) > 0;
}

export async function deleteIntegration(orgId: string, id: string) {
  const { rowCount } = await query(
    'DELETE FROM alert_integrations WHERE org_id = $1 AND id = $2', [orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

export async function getIntegrationsByType(orgId: string, type: string) {
  const { rows } = await query(
    'SELECT * FROM alert_integrations WHERE org_id = $1 AND type = $2 AND is_enabled = TRUE',
    [orgId, type]
  );
  return rows;
}

// ════════════════════════════════════════════
// NOTIFICATION LOG
// ════════════════════════════════════════════

export async function createNotificationLog(data: {
  event_id: string; escalation_id?: string; channel: string;
  recipient?: string; status?: string; last_error?: string;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO alert_notifications (event_id, escalation_id, channel, recipient, status, last_error)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [data.event_id, data.escalation_id ?? null, data.channel,
     data.recipient ?? null, data.status ?? 'pending', data.last_error ?? null]
  );
  return rows[0].id;
}

export async function updateNotificationStatus(id: string, status: string, error?: string) {
  await query(
    `UPDATE alert_notifications SET status = $2, last_error = $3, sent_at = CASE WHEN $2 = 'sent' THEN NOW() ELSE sent_at END
     WHERE id = $1`,
    [id, status, error ?? null]
  );
}

// ════════════════════════════════════════════
// ESCALATION LOGIC
// ════════════════════════════════════════════

export async function getEscalationsForRule(ruleId: string) {
  const { rows } = await query(
    'SELECT * FROM alert_escalations WHERE rule_id = $1 ORDER BY step', [ruleId]
  );
  return rows;
}

export async function advanceEscalation(eventId: string, nextStep: number) {
  await query(
    `UPDATE alert_events SET escalation_step = $2, last_escalated_at = NOW(), updated_at = NOW()
     WHERE id = $1`,
    [eventId, nextStep]
  );
}
