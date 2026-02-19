// ─────────────────────────────────────────────
// MASSVISION Reap3r — EDR Service
// ─────────────────────────────────────────────
import { query, transaction } from '../db/pool.js';

// ── Security events ──
export async function ingestSecurityEvent(orgId: string, agentId: string, event: {
  event_type: string; severity: string; details: Record<string, unknown>;
  process_name?: string; process_path?: string; pid?: number; parent_pid?: number;
  cmdline?: string; user?: string; sha256?: string;
  dest_ip?: string; dest_port?: number; dest_domain?: string;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO security_events
      (org_id, agent_id, event_type, severity, details, process_name, process_path,
       pid, parent_pid, cmdline, username, sha256, dest_ip, dest_port, dest_domain)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
    [orgId, agentId, event.event_type, event.severity, JSON.stringify(event.details),
     event.process_name ?? null, event.process_path ?? null,
     event.pid ?? null, event.parent_pid ?? null, event.cmdline ?? null,
     event.user ?? null, event.sha256 ?? null,
     event.dest_ip ?? null, event.dest_port ?? null, event.dest_domain ?? null]
  );
  const eventId = rows[0].id;

  // Run detection rules
  await runDetectionRules(orgId, agentId, eventId, event);

  return eventId;
}

export async function listSecurityEvents(orgId: string, params: {
  page: number; limit: number; agent_id?: string; event_type?: string; severity?: string;
}) {
  const conditions = ['se.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.agent_id) { conditions.push(`se.agent_id = $${idx}`); vals.push(params.agent_id); idx++; }
  if (params.event_type) { conditions.push(`se.event_type = $${idx}`); vals.push(params.event_type); idx++; }
  if (params.severity) { conditions.push(`se.severity = $${idx}`); vals.push(params.severity); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT se.*, a.hostname AS agent_hostname FROM security_events se
       LEFT JOIN agents a ON a.id = se.agent_id
       WHERE ${where} ORDER BY se.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM security_events se WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

// ── Detections ──
async function runDetectionRules(orgId: string, agentId: string, eventId: string, event: any) {
  const { rows: rules } = await query(
    `SELECT * FROM edr_rules WHERE is_active = TRUE AND (org_id IS NULL OR org_id = $1)`, [orgId]
  );

  for (const rule of rules) {
    if (matchesRule(rule, event)) {
      await query(
        `INSERT INTO detections (org_id, agent_id, event_id, rule_id, rule_name, severity, score, details)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [orgId, agentId, eventId, rule.rule_id, rule.name, rule.severity,
         severityToScore(rule.severity), JSON.stringify({ matched_rule: rule.rule_id })]
      );
    }
  }
}

function matchesRule(rule: any, event: any): boolean {
  try {
    const logic = typeof rule.logic === 'string' ? JSON.parse(rule.logic) : rule.logic;
    if (!logic?.match) return false;

    for (const [field, patterns] of Object.entries(logic.match)) {
      const value = String(event[field] ?? event.details?.[field] ?? '');
      if (!value) continue;
      for (const pattern of patterns as string[]) {
        if (value.toLowerCase().includes(pattern.toLowerCase())) return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

function severityToScore(severity: string): number {
  switch (severity) {
    case 'critical': return 100;
    case 'high': return 75;
    case 'medium': return 50;
    case 'low': return 25;
    default: return 0;
  }
}

export async function listDetections(orgId: string, params: {
  page: number; limit: number; status?: string; severity?: string; agent_id?: string;
}) {
  const conditions = ['d.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.status) { conditions.push(`d.status = $${idx}`); vals.push(params.status); idx++; }
  if (params.severity) { conditions.push(`d.severity = $${idx}`); vals.push(params.severity); idx++; }
  if (params.agent_id) { conditions.push(`d.agent_id = $${idx}`); vals.push(params.agent_id); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT d.*, a.hostname AS agent_hostname FROM detections d
       LEFT JOIN agents a ON a.id = d.agent_id
       WHERE ${where} ORDER BY d.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM detections d WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

export async function updateDetectionStatus(orgId: string, id: string, status: string, resolvedBy?: string) {
  const { rowCount } = await query(
    `UPDATE detections SET status = $1, resolved_by = $2, resolved_at = CASE WHEN $1 IN ('resolved','false_positive') THEN NOW() ELSE NULL END
     WHERE org_id = $3 AND id = $4`,
    [status, resolvedBy ?? null, orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

// ── Incidents ──
export async function createIncident(orgId: string, userId: string, data: {
  title: string; severity: string; detection_ids: string[]; assigned_to?: string; notes?: string;
}) {
  return transaction(async (client) => {
    const { rows } = await client.query(
      `INSERT INTO incidents (org_id, title, severity, assigned_to, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
      [orgId, data.title, data.severity, data.assigned_to ?? null, data.notes ?? null, userId]
    );
    const incidentId = rows[0].id;

    if (data.detection_ids.length) {
      const placeholders = data.detection_ids.map((_, i) => `($1, $${i + 2})`).join(', ');
      await client.query(
        `INSERT INTO incident_detections (incident_id, detection_id) VALUES ${placeholders}`,
        [incidentId, ...data.detection_ids]
      );
    }

    return { id: incidentId };
  });
}

export async function listIncidents(orgId: string, params: {
  page: number; limit: number; status?: string; severity?: string;
}) {
  const conditions = ['i.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.status) { conditions.push(`i.status = $${idx}`); vals.push(params.status); idx++; }
  if (params.severity) { conditions.push(`i.severity = $${idx}`); vals.push(params.severity); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT i.*,
         (SELECT COUNT(*) FROM incident_detections id2 WHERE id2.incident_id = i.id)::int AS detection_count
       FROM incidents i WHERE ${where} ORDER BY i.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM incidents i WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

export async function updateIncidentStatus(orgId: string, id: string, status: string) {
  const { rowCount } = await query(
    `UPDATE incidents SET status = $1, updated_at = NOW() WHERE org_id = $2 AND id = $3`,
    [status, orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

// ── Response actions ──
export async function createResponseAction(orgId: string, data: {
  agent_id: string;
  action: string;
  job_id?: string;
  initiated_by: string;
  reason: string;
  status?: string;
  result?: Record<string, unknown>;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO response_actions (org_id, agent_id, action, job_id, initiated_by, reason, status, result)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [
      orgId,
      data.agent_id,
      data.action,
      data.job_id ?? null,
      data.initiated_by,
      data.reason,
      data.status ?? 'pending',
      data.result ? JSON.stringify(data.result) : null,
    ],
  );
  return rows[0];
}

export type ResponseActionRow = {
  id: string;
  org_id: string;
  agent_id: string;
  action: string;
  job_id: string | null;
  initiated_by: string;
  reason: string;
  status: string;
  result: unknown;
  created_at: string;
};

export async function getResponseActionById(orgId: string, id: string): Promise<ResponseActionRow | null> {
  const { rows } = await query<ResponseActionRow>(
    `SELECT id, org_id, agent_id, action, job_id, initiated_by, reason, status, result, created_at
     FROM response_actions
     WHERE org_id = $1 AND id = $2
     LIMIT 1`,
    [orgId, id],
  );
  return rows[0] ?? null;
}

export async function isResponseApprovalConsumed(orgId: string, approvalId: string): Promise<boolean> {
  const { rowCount } = await query(
    `SELECT 1
     FROM response_actions
     WHERE org_id = $1
       AND result IS NOT NULL
       AND result->>'approval_id' = $2
     LIMIT 1`,
    [orgId, approvalId],
  );
  return (rowCount ?? 0) > 0;
}
