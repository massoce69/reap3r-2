// ─────────────────────────────────────────────
// MASSVISION Reap3r — EDR Service v2 (Market-grade)
// ─────────────────────────────────────────────
import { query, transaction } from '../db/pool.js';

// ══════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════
export interface EdrEvent {
  event_type: string;
  ts?: string;
  pid?: number;
  ppid?: number;
  image?: string;
  cmdline?: string;
  username?: string;
  integrity?: string;
  signer?: string;
  sha256?: string;
  parent_image?: string;
  parent_cmdline?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  dns_query?: string;
  file_path?: string;
  file_op?: string;
  file_hash?: string;
  file_size?: number;
  persist_type?: string;
  persist_key?: string;
  persist_value?: string;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  tags?: string[];
  severity?: string;
  raw?: Record<string, unknown>;
  sensor_queue_depth?: number;
  sensor_dropped?: number;
  // Legacy fields (backward compat)
  process_name?: string;
  process_path?: string;
  parent_pid?: number;
  dest_ip?: string;
  dest_port?: number;
  dest_domain?: string;
  user?: string;
  details?: Record<string, unknown>;
}

export interface RuleRow {
  id: string;
  rule_id: string;
  name: string;
  description: string | null;
  severity: string;
  logic: unknown;
  is_active: boolean;
  is_builtin: boolean;
  org_id: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  event_types: string[];
  tags: string[];
  dedup_window_sec: number;
  threshold_count: number;
  threshold_window_sec: number;
  monitor_only: boolean;
}

// ══════════════════════════════════════════════
// 1) EDR EVENT INGESTION (dual-write: legacy + v2)
// ══════════════════════════════════════════════
export async function ingestSecurityEvent(orgId: string, agentId: string, event: EdrEvent) {
  // Normalize legacy fields
  const image = event.image ?? event.process_path ?? null;
  const cmdline = event.cmdline ?? null;
  const username = event.username ?? event.user ?? null;
  const dstIp = event.dst_ip ?? event.dest_ip ?? null;
  const dstPort = event.dst_port ?? event.dest_port ?? null;
  const severity = event.severity ?? 'info';

  // Write to legacy security_events table (backward compat)
  const { rows: legacyRows } = await query<{ id: string }>(
    `INSERT INTO security_events
      (org_id, agent_id, event_type, severity, details, process_name, process_path,
       pid, parent_pid, cmdline, username, sha256, dest_ip, dest_port, dest_domain)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
    [orgId, agentId, event.event_type, severity, JSON.stringify(event.details ?? event.raw ?? {}),
     event.process_name ?? (image ? image.split(/[/\\]/).pop() : null), image,
     event.pid ?? null, event.ppid ?? event.parent_pid ?? null, cmdline,
     username, event.sha256 ?? null,
     dstIp, dstPort, event.dest_domain ?? event.dns_query ?? null]
  );

  // Write to normalized edr_events table
  let edrEventId: string | null = null;
  try {
    const { rows: edrRows } = await query<{ id: string }>(
      `INSERT INTO edr_events
        (org_id, agent_id, event_type, ts, pid, ppid, image, cmdline, username,
         integrity, signer, sha256, parent_image, parent_cmdline,
         src_ip, src_port, dst_ip, dst_port, protocol, dns_query,
         file_path, file_op, file_hash, file_size,
         persist_type, persist_key, persist_value,
         mitre_tactics, mitre_techniques, tags, severity, raw,
         sensor_queue_depth, sensor_dropped)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)
       RETURNING id`,
      [
        orgId, agentId, event.event_type, event.ts ? new Date(event.ts) : new Date(),
        event.pid ?? null, event.ppid ?? null, image, cmdline, username,
        event.integrity ?? null, event.signer ?? null, event.sha256 ?? null,
        event.parent_image ?? null, event.parent_cmdline ?? null,
        event.src_ip ?? null, event.src_port ?? null, dstIp, dstPort,
        event.protocol ?? null, event.dns_query ?? null,
        event.file_path ?? null, event.file_op ?? null, event.file_hash ?? null, event.file_size ?? null,
        event.persist_type ?? null, event.persist_key ?? null, event.persist_value ?? null,
        event.mitre_tactics ?? null, event.mitre_techniques ?? null, event.tags ?? null,
        severity, event.raw ? JSON.stringify(event.raw) : null,
        event.sensor_queue_depth ?? null, event.sensor_dropped ?? null,
      ]
    );
    edrEventId = edrRows[0]?.id ?? null;
  } catch {
    // edr_events table may not exist on older DBs — continue with legacy only
  }

  const eventId = legacyRows[0].id;

  // Run detection rules
  await runDetectionRules(orgId, agentId, eventId, event);

  return eventId;
}

// Batch ingest (agent sends batch of events)
export async function ingestEventBatch(orgId: string, agentId: string, events: EdrEvent[]) {
  const ids: string[] = [];
  for (const event of events) {
    const id = await ingestSecurityEvent(orgId, agentId, event);
    ids.push(id);
  }
  return ids;
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

// ══════════════════════════════════════════════
// 2) DETECTION ENGINE v2
// ══════════════════════════════════════════════
async function runDetectionRules(orgId: string, agentId: string, eventId: string, event: EdrEvent) {
  const { rows: rules } = await query<RuleRow>(
    `SELECT * FROM edr_rules WHERE (is_active = TRUE OR is_enabled = TRUE) AND (org_id IS NULL OR org_id = $1)`,
    [orgId]
  );

  for (const rule of rules) {
    // Check event type filter
    if (rule.event_types?.length > 0 && !rule.event_types.includes(event.event_type)) continue;

    if (matchesRule(rule, event)) {
      // Check exceptions / allowlists
      const excepted = await checkExceptions(orgId, agentId, rule.rule_id, event);
      if (excepted) continue;

      // Dedup check: don't fire same rule for same agent within dedup window
      const dedupWindowSec = rule.dedup_window_sec || 300;
      const { rows: existing } = await query(
        `SELECT id FROM detections
         WHERE org_id = $1 AND agent_id = $2 AND rule_id = $3
           AND status NOT IN ('resolved', 'false_positive')
           AND created_at > NOW() - interval '1 second' * $4
         LIMIT 1`,
        [orgId, agentId, rule.rule_id, dedupWindowSec]
      );
      if (existing.length > 0) continue;

      // Threshold check: require N events in T seconds
      if (rule.threshold_count > 1 && rule.threshold_window_sec > 0) {
        const { rows: countRows } = await query<{ cnt: number }>(
          `SELECT COUNT(*)::int AS cnt FROM security_events
           WHERE org_id = $1 AND agent_id = $2 AND event_type = $3
             AND created_at > NOW() - interval '1 second' * $4`,
          [orgId, agentId, event.event_type, rule.threshold_window_sec]
        );
        if ((countRows[0]?.cnt ?? 0) < rule.threshold_count) continue;
      }

      // Insert detection
      const score = severityToScore(rule.severity);
      const status = rule.monitor_only ? 'monitoring' : 'open';

      const { rows: detRows } = await query<{ id: string }>(
        `INSERT INTO detections (org_id, agent_id, event_id, rule_id, rule_name, severity, score, status, details)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
        [orgId, agentId, eventId, rule.rule_id, rule.name, rule.severity, score, status,
         JSON.stringify({
           matched_rule: rule.rule_id,
           mitre_tactic: rule.mitre_tactic,
           mitre_technique: rule.mitre_technique,
           event_type: event.event_type,
           image: event.image ?? event.process_path,
           cmdline: event.cmdline,
           pid: event.pid,
           username: event.username ?? event.user,
           sha256: event.sha256,
           dst_ip: event.dst_ip ?? event.dest_ip,
           file_path: event.file_path,
         })]
      );

      // Auto-create or link to incident for high/critical detections (non-monitor)
      if (!rule.monitor_only && (rule.severity === 'critical' || rule.severity === 'high')) {
        await autoCreateOrLinkIncident(orgId, agentId, detRows[0].id, rule);
      }
    }
  }
}

// Advanced rule matching with conditions, ANY_match, regex, NOT support
function matchesRule(rule: RuleRow, event: EdrEvent): boolean {
  try {
    const logic = typeof rule.logic === 'string' ? JSON.parse(rule.logic) : rule.logic;
    if (!logic) return false;

    // Check conditions first (all must match)
    if (logic.conditions) {
      for (const [field, expected] of Object.entries(logic.conditions)) {
        const value = getEventField(event, field);
        if (!value) return false;
        const patterns = Array.isArray(expected) ? expected : [expected];
        const matched = patterns.some((p: string) =>
          value.toLowerCase().includes(String(p).toLowerCase())
        );
        if (!matched) return false;
      }
    }

    // Check NOT conditions (none must match)
    if (logic.not) {
      for (const [field, patterns] of Object.entries(logic.not)) {
        const value = getEventField(event, field);
        if (!value) continue;
        for (const pattern of patterns as string[]) {
          if (value.toLowerCase().includes(pattern.toLowerCase())) return false;
        }
      }
    }

    // Check match (any pattern in any field = match)
    if (logic.match) {
      let anyMatch = false;
      for (const [field, patterns] of Object.entries(logic.match)) {
        const value = getEventField(event, field);
        if (!value) continue;
        for (const pattern of patterns as string[]) {
          if (value.toLowerCase().includes(pattern.toLowerCase())) {
            anyMatch = true;
            break;
          }
        }
        if (anyMatch) break;
      }
      if (!anyMatch) return false;
    }

    // Check ANY_match (alternative fields — if any match, rule fires)
    if (logic.ANY_match) {
      for (const [field, patterns] of Object.entries(logic.ANY_match)) {
        const value = getEventField(event, field);
        if (!value) continue;
        for (const pattern of patterns as string[]) {
          if (value.toLowerCase().includes(pattern.toLowerCase())) return true;
        }
      }
    }

    // Check regex patterns
    if (logic.regex) {
      for (const [field, pattern] of Object.entries(logic.regex)) {
        const value = getEventField(event, field);
        if (!value) continue;
        try {
          if (new RegExp(pattern as string, 'i').test(value)) return true;
        } catch { /* invalid regex — skip */ }
      }
    }

    return logic.match ? true : false;
  } catch {
    return false;
  }
}

function getEventField(event: EdrEvent, field: string): string {
  // Check direct fields
  const directValue = (event as any)[field];
  if (directValue != null) return String(directValue);
  // Check details sub-object
  const detailValue = event.details?.[field];
  if (detailValue != null) return String(detailValue);
  // Check raw sub-object
  const rawValue = event.raw?.[field];
  if (rawValue != null) return String(rawValue);
  return '';
}

async function checkExceptions(orgId: string, agentId: string, ruleId: string, event: EdrEvent): Promise<boolean> {
  const { rows } = await query(
    `SELECT * FROM edr_rule_exceptions
     WHERE org_id = $1 AND rule_id = $2
       AND (expires_at IS NULL OR expires_at > NOW())
       AND (
         scope = 'org'
         OR (scope = 'device' AND scope_id = $3::uuid)
       )`, [orgId, ruleId, agentId]
  );

  for (const exc of rows) {
    const value = getEventField(event, exc.field);
    if (!value) continue;
    if (exc.is_regex) {
      try {
        if (new RegExp(exc.pattern, 'i').test(value)) return true;
      } catch { /* skip bad regex */ }
    } else {
      if (value.toLowerCase().includes(String(exc.pattern).toLowerCase())) return true;
    }
  }
  return false;
}

async function autoCreateOrLinkIncident(orgId: string, agentId: string, detectionId: string, rule: RuleRow) {
  // Check for existing open incident for this agent (within 1 hour window)
  const { rows: existing } = await query<{ id: string }>(
    `SELECT i.id FROM incidents i
     JOIN incident_detections id2 ON id2.incident_id = i.id
     JOIN detections d ON d.id = id2.detection_id
     WHERE i.org_id = $1 AND i.status NOT IN ('resolved', 'closed')
       AND d.agent_id = $2
       AND i.created_at > NOW() - interval '1 hour'
     LIMIT 1`,
    [orgId, agentId]
  );

  if (existing.length > 0) {
    // Link to existing incident
    const incidentId = existing[0].id;
    await query(
      `INSERT INTO incident_detections (incident_id, detection_id) VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [incidentId, detectionId]
    );
    // Update incident risk score
    await query(
      `UPDATE incidents SET risk_score = GREATEST(risk_score, $1), updated_at = NOW(),
         severity = CASE WHEN $2 = 'critical' THEN 'critical' ELSE severity END
       WHERE id = $3`,
      [severityToScore(rule.severity), rule.severity, incidentId]
    );
    // Add timeline entry
    try {
      await query(
        `INSERT INTO edr_incident_timeline (incident_id, entry_type, ref_id, summary, metadata)
         VALUES ($1, 'detection', $2, $3, $4)`,
        [incidentId, detectionId,
         `Detection: ${rule.name} (${rule.severity})`,
         JSON.stringify({ rule_id: rule.rule_id, mitre: rule.mitre_technique })]
      );
    } catch { /* timeline table may not exist */ }
  } else {
    // Create new incident
    const mitreTactics = rule.mitre_tactic ? [rule.mitre_tactic] : [];
    const mitreTechniques = rule.mitre_technique ? [rule.mitre_technique] : [];

    const { rows: inc } = await query<{ id: string }>(
      `INSERT INTO incidents (org_id, title, severity, risk_score, agent_id, auto_created, mitre_tactics, mitre_techniques)
       VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7) RETURNING id`,
      [orgId, `[Auto] ${rule.name}`, rule.severity, severityToScore(rule.severity), agentId,
       mitreTactics, mitreTechniques]
    );
    await query(
      `INSERT INTO incident_detections (incident_id, detection_id) VALUES ($1, $2)`,
      [inc[0].id, detectionId]
    );
    try {
      await query(
        `INSERT INTO edr_incident_timeline (incident_id, entry_type, ref_id, summary, metadata)
         VALUES ($1, 'detection', $2, $3, $4)`,
        [inc[0].id, detectionId,
         `Incident auto-created from detection: ${rule.name}`,
         JSON.stringify({ rule_id: rule.rule_id, mitre: rule.mitre_technique })]
      );
    } catch { /* timeline table may not exist */ }
  }
}

function severityToScore(severity: string): number {
  switch (severity) {
    case 'critical': return 100;
    case 'high': return 75;
    case 'medium': return 50;
    case 'low': return 25;
    default: return 10;
  }
}

// ══════════════════════════════════════════════
// 3) DETECTIONS
// ══════════════════════════════════════════════
export async function listDetections(orgId: string, params: {
  page: number; limit: number; status?: string; severity?: string; agent_id?: string; rule_id?: string;
}) {
  const conditions = ['d.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.status) { conditions.push(`d.status = $${idx}`); vals.push(params.status); idx++; }
  if (params.severity) { conditions.push(`d.severity = $${idx}`); vals.push(params.severity); idx++; }
  if (params.agent_id) { conditions.push(`d.agent_id = $${idx}`); vals.push(params.agent_id); idx++; }
  if (params.rule_id) { conditions.push(`d.rule_id = $${idx}`); vals.push(params.rule_id); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT d.*, a.hostname AS agent_hostname,
         se.cmdline AS event_cmdline, se.process_name AS event_process_name,
         se.process_path AS event_process_path, se.pid AS event_pid,
         se.parent_pid AS event_parent_pid, se.username AS event_username, se.sha256 AS event_sha256
       FROM detections d
       LEFT JOIN agents a ON a.id = d.agent_id
       LEFT JOIN security_events se ON se.id = d.event_id
       WHERE ${where} ORDER BY d.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM detections d WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

export async function getDetectionById(orgId: string, id: string) {
  const { rows } = await query(
    `SELECT d.*, a.hostname AS agent_hostname,
       se.cmdline AS event_cmdline, se.process_name AS event_process_name,
       se.process_path AS event_process_path, se.pid AS event_pid,
       se.parent_pid AS event_parent_pid, se.username AS event_username,
       se.sha256 AS event_sha256, se.dest_ip AS event_dest_ip,
       se.dest_port AS event_dest_port, se.details AS event_details
     FROM detections d
     LEFT JOIN agents a ON a.id = d.agent_id
     LEFT JOIN security_events se ON se.id = d.event_id
     WHERE d.org_id = $1 AND d.id = $2`,
    [orgId, id]
  );
  return rows[0] ?? null;
}

export async function updateDetectionStatus(orgId: string, id: string, status: string, resolvedBy?: string) {
  const { rowCount } = await query(
    `UPDATE detections SET status = $1, resolved_by = $2, resolved_at = CASE WHEN $1 IN ('resolved','false_positive') THEN NOW() ELSE NULL END
     WHERE org_id = $3 AND id = $4`,
    [status, resolvedBy ?? null, orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

// ══════════════════════════════════════════════
// 4) INCIDENTS
// ══════════════════════════════════════════════
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

    // Add timeline entry
    try {
      await client.query(
        `INSERT INTO edr_incident_timeline (incident_id, entry_type, actor, summary)
         VALUES ($1, 'note', $2, $3)`,
        [incidentId, userId, `Incident created: ${data.title}`]
      );
    } catch { /* timeline table may not exist */ }

    return { id: incidentId };
  });
}

export async function getIncidentById(orgId: string, id: string) {
  const { rows } = await query(
    `SELECT i.*,
       (SELECT COUNT(*) FROM incident_detections id2 WHERE id2.incident_id = i.id)::int AS detection_count,
       (SELECT json_agg(json_build_object(
         'id', d.id, 'rule_id', d.rule_id, 'rule_name', d.rule_name,
         'severity', d.severity, 'status', d.status, 'score', d.score,
         'agent_id', d.agent_id, 'created_at', d.created_at,
         'details', d.details
       )) FROM detections d
       JOIN incident_detections id3 ON id3.detection_id = d.id
       WHERE id3.incident_id = i.id) AS detections,
       a.hostname AS agent_hostname
     FROM incidents i
     LEFT JOIN agents a ON a.id = i.agent_id
     WHERE i.org_id = $1 AND i.id = $2`,
    [orgId, id]
  );
  return rows[0] ?? null;
}

export async function listIncidents(orgId: string, params: {
  page: number; limit: number; status?: string; severity?: string; agent_id?: string;
}) {
  const conditions = ['i.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.status) { conditions.push(`i.status = $${idx}`); vals.push(params.status); idx++; }
  if (params.severity) { conditions.push(`i.severity = $${idx}`); vals.push(params.severity); idx++; }
  if (params.agent_id) { conditions.push(`i.agent_id = $${idx}`); vals.push(params.agent_id); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT i.*,
         (SELECT COUNT(*) FROM incident_detections id2 WHERE id2.incident_id = i.id)::int AS detection_count,
         a.hostname AS agent_hostname
       FROM incidents i
       LEFT JOIN agents a ON a.id = i.agent_id
       WHERE ${where} ORDER BY i.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM incidents i WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

export async function updateIncidentStatus(orgId: string, id: string, status: string, userId?: string) {
  const { rowCount } = await query(
    `UPDATE incidents SET status = $1, updated_at = NOW(),
       closed_at = CASE WHEN $1 IN ('resolved','closed') THEN NOW() ELSE closed_at END
     WHERE org_id = $2 AND id = $3`,
    [status, orgId, id]
  );
  // Add timeline entry
  try {
    await query(
      `INSERT INTO edr_incident_timeline (incident_id, entry_type, actor, summary)
       VALUES ($1, 'status_change', $2, $3)`,
      [id, userId ?? null, `Status changed to: ${status}`]
    );
  } catch { /* timeline table may not exist */ }
  return (rowCount ?? 0) > 0;
}

export async function getIncidentTimeline(orgId: string, incidentId: string) {
  const { rows } = await query(
    `SELECT t.*, u.name AS actor_name
     FROM edr_incident_timeline t
     LEFT JOIN users u ON u.id = t.actor
     WHERE t.incident_id = $1
     ORDER BY t.ts ASC`,
    [incidentId]
  );
  return rows;
}

export async function addIncidentTimelineEntry(incidentId: string, entryType: string, summary: string, actor?: string, refId?: string, metadata?: Record<string, unknown>) {
  await query(
    `INSERT INTO edr_incident_timeline (incident_id, entry_type, ref_id, summary, actor, metadata)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [incidentId, entryType, refId ?? null, summary, actor ?? null, metadata ? JSON.stringify(metadata) : null]
  );
}

// ══════════════════════════════════════════════
// 5) EDR RULES CRUD
// ══════════════════════════════════════════════
export async function listRules(orgId: string) {
  const { rows } = await query(
    `SELECT * FROM edr_rules WHERE org_id IS NULL OR org_id = $1
     ORDER BY is_builtin DESC, severity DESC, name ASC`,
    [orgId]
  );
  return rows;
}

export async function getRuleById(orgId: string, ruleId: string) {
  const { rows } = await query(
    `SELECT * FROM edr_rules WHERE (org_id IS NULL OR org_id = $1) AND (id = $2 OR rule_id = $2) LIMIT 1`,
    [orgId, ruleId]
  );
  return rows[0] ?? null;
}

export async function createRule(orgId: string, data: {
  rule_id: string; name: string; description?: string; severity: string;
  logic: unknown; event_types?: string[]; mitre_tactic?: string; mitre_technique?: string;
  tags?: string[]; dedup_window_sec?: number; threshold_count?: number; threshold_window_sec?: number;
  monitor_only?: boolean;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO edr_rules (org_id, rule_id, name, description, severity, logic, is_builtin, is_active,
       event_types, mitre_tactic, mitre_technique, tags, dedup_window_sec, threshold_count, threshold_window_sec, monitor_only)
     VALUES ($1,$2,$3,$4,$5,$6,FALSE,TRUE,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING id`,
    [orgId, data.rule_id, data.name, data.description ?? null, data.severity, JSON.stringify(data.logic),
     data.event_types ?? [], data.mitre_tactic ?? null, data.mitre_technique ?? null,
     data.tags ?? [], data.dedup_window_sec ?? 300, data.threshold_count ?? 1,
     data.threshold_window_sec ?? 0, data.monitor_only ?? false]
  );
  return rows[0];
}

export async function updateRule(orgId: string, id: string, data: {
  name?: string; description?: string; severity?: string; logic?: unknown;
  is_active?: boolean; event_types?: string[]; mitre_tactic?: string; mitre_technique?: string;
  tags?: string[]; dedup_window_sec?: number; threshold_count?: number; threshold_window_sec?: number;
  monitor_only?: boolean;
}) {
  const fields: string[] = ['updated_at = NOW()'];
  const params: unknown[] = [orgId, id];
  let idx = 3;

  if (data.name !== undefined) { fields.push(`name = $${idx++}`); params.push(data.name); }
  if (data.description !== undefined) { fields.push(`description = $${idx++}`); params.push(data.description); }
  if (data.severity !== undefined) { fields.push(`severity = $${idx++}`); params.push(data.severity); }
  if (data.logic !== undefined) { fields.push(`logic = $${idx++}`); params.push(JSON.stringify(data.logic)); }
  if (data.is_active !== undefined) { fields.push(`is_active = $${idx++}`); params.push(data.is_active); }
  if (data.event_types !== undefined) { fields.push(`event_types = $${idx++}`); params.push(data.event_types); }
  if (data.mitre_tactic !== undefined) { fields.push(`mitre_tactic = $${idx++}`); params.push(data.mitre_tactic); }
  if (data.mitre_technique !== undefined) { fields.push(`mitre_technique = $${idx++}`); params.push(data.mitre_technique); }
  if (data.tags !== undefined) { fields.push(`tags = $${idx++}`); params.push(data.tags); }
  if (data.dedup_window_sec !== undefined) { fields.push(`dedup_window_sec = $${idx++}`); params.push(data.dedup_window_sec); }
  if (data.threshold_count !== undefined) { fields.push(`threshold_count = $${idx++}`); params.push(data.threshold_count); }
  if (data.threshold_window_sec !== undefined) { fields.push(`threshold_window_sec = $${idx++}`); params.push(data.threshold_window_sec); }
  if (data.monitor_only !== undefined) { fields.push(`monitor_only = $${idx++}`); params.push(data.monitor_only); }

  const { rowCount } = await query(
    `UPDATE edr_rules SET ${fields.join(', ')} WHERE org_id = $1 AND (id = $2 OR rule_id = $2)`,
    params
  );
  return (rowCount ?? 0) > 0;
}

export async function deleteRule(orgId: string, id: string) {
  const { rowCount } = await query(
    `DELETE FROM edr_rules WHERE org_id = $1 AND (id = $2 OR rule_id = $2) AND is_builtin = FALSE`,
    [orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

// ══════════════════════════════════════════════
// 6) RULE EXCEPTIONS
// ══════════════════════════════════════════════
export async function listExceptions(orgId: string, ruleId?: string) {
  const conditions = ['org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;
  if (ruleId) { conditions.push(`rule_id = $${idx++}`); vals.push(ruleId); }
  const { rows } = await query(
    `SELECT * FROM edr_rule_exceptions WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC`,
    vals
  );
  return rows;
}

export async function createException(orgId: string, data: {
  rule_id: string; scope: string; scope_id?: string; field: string; pattern: string;
  is_regex?: boolean; reason?: string; created_by?: string; expires_at?: string;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO edr_rule_exceptions (org_id, rule_id, scope, scope_id, field, pattern, is_regex, reason, created_by, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
    [orgId, data.rule_id, data.scope, data.scope_id ?? null, data.field, data.pattern,
     data.is_regex ?? false, data.reason ?? null, data.created_by ?? null,
     data.expires_at ? new Date(data.expires_at) : null]
  );
  return rows[0];
}

export async function deleteException(orgId: string, id: string) {
  const { rowCount } = await query(
    `DELETE FROM edr_rule_exceptions WHERE org_id = $1 AND id = $2`, [orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

// ══════════════════════════════════════════════
// 7) THREAT HUNTING
// ══════════════════════════════════════════════
export async function hunt(orgId: string, params: {
  q?: string; event_type?: string; agent_id?: string; sha256?: string;
  dst_ip?: string; image?: string; cmdline?: string;
  from?: string; to?: string; page: number; limit: number;
}) {
  const conditions = ['org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  // Use edr_events if available, fallback to security_events
  const table = 'security_events';

  if (params.event_type) { conditions.push(`event_type = $${idx++}`); vals.push(params.event_type); }
  if (params.agent_id) { conditions.push(`agent_id = $${idx++}`); vals.push(params.agent_id); }
  if (params.sha256) { conditions.push(`sha256 = $${idx++}`); vals.push(params.sha256); }
  if (params.dst_ip) { conditions.push(`dest_ip = $${idx++}`); vals.push(params.dst_ip); }

  // Full-text search across cmdline, process_path, process_name
  if (params.q) {
    conditions.push(`(
      cmdline ILIKE '%' || $${idx} || '%'
      OR process_name ILIKE '%' || $${idx} || '%'
      OR process_path ILIKE '%' || $${idx} || '%'
      OR sha256 = $${idx}
      OR dest_ip = $${idx}
      OR dest_domain ILIKE '%' || $${idx} || '%'
      OR username ILIKE '%' || $${idx} || '%'
    )`);
    vals.push(params.q);
    idx++;
  }

  if (params.image) {
    conditions.push(`process_path ILIKE '%' || $${idx} || '%'`);
    vals.push(params.image);
    idx++;
  }
  if (params.cmdline) {
    conditions.push(`cmdline ILIKE '%' || $${idx} || '%'`);
    vals.push(params.cmdline);
    idx++;
  }
  if (params.from) { conditions.push(`created_at >= $${idx++}`); vals.push(new Date(params.from)); }
  if (params.to) { conditions.push(`created_at <= $${idx++}`); vals.push(new Date(params.to)); }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT se.*, a.hostname AS agent_hostname
       FROM ${table} se
       LEFT JOIN agents a ON a.id = se.agent_id
       WHERE ${where}
       ORDER BY se.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM ${table} se WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

// Saved hunt queries
export async function listHuntQueries(orgId: string, userId: string) {
  const { rows } = await query(
    `SELECT * FROM edr_hunt_queries WHERE org_id = $1 AND (created_by = $2 OR is_shared = TRUE) ORDER BY updated_at DESC`,
    [orgId, userId]
  );
  return rows;
}

export async function saveHuntQuery(orgId: string, userId: string, data: {
  name: string; description?: string; query: unknown; is_shared?: boolean;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO edr_hunt_queries (org_id, name, description, query, created_by, is_shared)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [orgId, data.name, data.description ?? null, JSON.stringify(data.query), userId, data.is_shared ?? false]
  );
  return rows[0];
}

export async function deleteHuntQuery(orgId: string, id: string) {
  const { rowCount } = await query(
    `DELETE FROM edr_hunt_queries WHERE org_id = $1 AND id = $2`, [orgId, id]
  );
  return (rowCount ?? 0) > 0;
}

// ══════════════════════════════════════════════
// 8) DEVICE ISOLATION STATE
// ══════════════════════════════════════════════
export async function getIsolationState(orgId: string, agentId: string) {
  const { rows } = await query(
    `SELECT * FROM device_isolation_state WHERE org_id = $1 AND agent_id = $2`,
    [orgId, agentId]
  );
  return rows[0] ?? null;
}

export async function setIsolationState(orgId: string, agentId: string, isolated: boolean, userId: string, reason: string, jobId?: string) {
  await query(
    `INSERT INTO device_isolation_state (agent_id, org_id, is_isolated, isolated_at, isolated_by, reason, job_id)
     VALUES ($1, $2, $3, CASE WHEN $3 THEN NOW() ELSE NULL END, $4, $5, $6)
     ON CONFLICT (agent_id) DO UPDATE SET
       is_isolated = $3,
       isolated_at = CASE WHEN $3 THEN NOW() ELSE device_isolation_state.isolated_at END,
       isolated_by = CASE WHEN $3 THEN $4 ELSE device_isolation_state.isolated_by END,
       reason = $5,
       job_id = $6,
       released_at = CASE WHEN NOT $3 THEN NOW() ELSE NULL END,
       released_by = CASE WHEN NOT $3 THEN $4 ELSE NULL END`,
    [agentId, orgId, isolated, userId, reason, jobId ?? null]
  );
}

export async function listIsolatedDevices(orgId: string) {
  const { rows } = await query(
    `SELECT dis.*, a.hostname, a.os, a.status AS agent_status
     FROM device_isolation_state dis
     JOIN agents a ON a.id = dis.agent_id
     WHERE dis.org_id = $1 AND dis.is_isolated = TRUE
     ORDER BY dis.isolated_at DESC`,
    [orgId]
  );
  return rows;
}

// ══════════════════════════════════════════════
// 9) QUARANTINE REGISTRY
// ══════════════════════════════════════════════
export async function addQuarantineEntry(orgId: string, data: {
  agent_id: string; original_path: string; sha256: string; file_size?: number;
  quarantine_path?: string; reason: string; quarantined_by: string; job_id?: string;
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO edr_quarantine (org_id, agent_id, original_path, sha256, file_size, quarantine_path, reason, quarantined_by, job_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
    [orgId, data.agent_id, data.original_path, data.sha256, data.file_size ?? null,
     data.quarantine_path ?? null, data.reason, data.quarantined_by, data.job_id ?? null]
  );
  return rows[0];
}

export async function listQuarantine(orgId: string, agentId?: string) {
  const conditions = ['org_id = $1'];
  const vals: unknown[] = [orgId];
  if (agentId) { conditions.push('agent_id = $2'); vals.push(agentId); }
  const { rows } = await query(
    `SELECT q.*, a.hostname AS agent_hostname
     FROM edr_quarantine q
     LEFT JOIN agents a ON a.id = q.agent_id
     WHERE ${conditions.join(' AND ')} ORDER BY q.quarantined_at DESC`,
    vals
  );
  return rows;
}

// ══════════════════════════════════════════════
// 10) EDR OVERVIEW STATS
// ══════════════════════════════════════════════
export async function getEdrOverview(orgId: string) {
  const [events24h, detectionsOpen, incidentsOpen, isolatedDevices, topRules] = await Promise.all([
    query<{ total: number }>(
      `SELECT COUNT(*)::int AS total FROM security_events WHERE org_id = $1 AND created_at > NOW() - interval '24 hours'`,
      [orgId]
    ),
    query<{ total: number; crit: number; high: number; med: number; low: number }>(
      `SELECT COUNT(*)::int AS total,
         COUNT(*) FILTER (WHERE severity = 'critical')::int AS crit,
         COUNT(*) FILTER (WHERE severity = 'high')::int AS high,
         COUNT(*) FILTER (WHERE severity = 'medium')::int AS med,
         COUNT(*) FILTER (WHERE severity = 'low')::int AS low
       FROM detections WHERE org_id = $1 AND status = 'open'`,
      [orgId]
    ),
    query<{ total: number }>(
      `SELECT COUNT(*)::int AS total FROM incidents WHERE org_id = $1 AND status NOT IN ('resolved', 'closed')`,
      [orgId]
    ),
    query<{ total: number }>(
      `SELECT COUNT(*)::int AS total FROM device_isolation_state WHERE org_id = $1 AND is_isolated = TRUE`,
      [orgId]
    ),
    query(
      `SELECT rule_id, rule_name, severity, COUNT(*)::int AS hit_count
       FROM detections WHERE org_id = $1 AND created_at > NOW() - interval '7 days'
       GROUP BY rule_id, rule_name, severity ORDER BY hit_count DESC LIMIT 10`,
      [orgId]
    ),
  ]);

  return {
    events_24h: events24h.rows[0]?.total ?? 0,
    detections_open: detectionsOpen.rows[0] ?? { total: 0, crit: 0, high: 0, med: 0, low: 0 },
    incidents_open: incidentsOpen.rows[0]?.total ?? 0,
    isolated_devices: isolatedDevices.rows[0]?.total ?? 0,
    top_rules_7d: topRules.rows,
  };
}

// ══════════════════════════════════════════════
// 11) RESPONSE ACTIONS (from original)
// ══════════════════════════════════════════════
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

export async function listResponseActions(orgId: string, params: {
  page: number; limit: number; agent_id?: string; action?: string;
}) {
  const conditions = ['ra.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.agent_id) { conditions.push(`ra.agent_id = $${idx++}`); vals.push(params.agent_id); }
  if (params.action) { conditions.push(`ra.action = $${idx++}`); vals.push(params.action); }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT ra.*, a.hostname AS agent_hostname, u.name AS initiator_name
       FROM response_actions ra
       LEFT JOIN agents a ON a.id = ra.agent_id
       LEFT JOIN users u ON u.id = ra.initiated_by
       WHERE ${where} ORDER BY ra.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM response_actions ra WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
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
