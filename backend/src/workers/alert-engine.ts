// ─────────────────────────────────────────────
// MASSVISION Reap3r — Alert Engine Worker
// Periodically evaluates alert rules, fires events,
// manages escalation, and dispatches notifications.
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';
import * as alertSvc from '../services/alerting.service.js';
import * as notifier from '../services/notification.service.js';
import { config } from '../config.js';

let engineTimer: ReturnType<typeof setInterval> | null = null;
let escalationTimer: ReturnType<typeof setInterval> | null = null;
let snoozeTimer: ReturnType<typeof setInterval> | null = null;

// ════════════════════════════════════════════
// RULE EVALUATION
// ════════════════════════════════════════════

async function evaluateRules(): Promise<void> {
  try {
    // Fetch all enabled rules across all orgs
    const { rows: rules } = await query(
      `SELECT r.*, o.id AS org_id FROM alert_rules r
       JOIN orgs o ON o.id = r.org_id
       WHERE r.is_enabled = TRUE`
    );

    for (const rule of rules) {
      try {
        await evaluateRule(rule);
      } catch (err: any) {
        console.error(`[alert-engine] Error evaluating rule ${rule.id}:`, err.message);
      }
    }
  } catch (err: any) {
    console.error('[alert-engine] Rule evaluation cycle failed:', err.message);
  }
}

async function evaluateRule(rule: any): Promise<void> {
  switch (rule.rule_type) {
    case 'agent_offline':
      await evaluateAgentOffline(rule);
      break;
    case 'job_failed':
      await evaluateJobFailed(rule);
      break;
    case 'edr_critical':
      await evaluateEdrCritical(rule);
      break;
    case 'tamper_detected':
      await evaluateTamperDetected(rule);
      break;
    case 'metric_threshold':
      await evaluateMetricThreshold(rule);
      break;
    default:
      break;
  }
}

// ── Agent Offline > X minutes ──
async function evaluateAgentOffline(rule: any): Promise<void> {
  const thresholdMin = rule.params?.threshold_minutes ?? 10;
  const scopeFilter = buildScopeFilter(rule, 'a');

  const { rows: offlineAgents } = await query(
    `SELECT a.id, a.hostname, a.company_id, a.last_seen_at, a.org_id
     FROM agents a
     WHERE a.org_id = $1
       AND a.status != 'offline'
       AND a.last_seen_at < NOW() - INTERVAL '${thresholdMin} minutes'
       ${scopeFilter}
     LIMIT 100`,
    [rule.org_id]
  );

  for (const agent of offlineAgents) {
    const fingerprint = `agent_offline:${agent.id}`;
    const result = await alertSvc.createAlertEvent({
      org_id: rule.org_id,
      rule_id: rule.id,
      rule_name: rule.name,
      entity_type: 'agent',
      entity_id: agent.id,
      fingerprint,
      severity: rule.severity,
      title: `Agent offline: ${agent.hostname}`,
      details: {
        hostname: agent.hostname,
        last_seen_at: agent.last_seen_at,
        threshold_minutes: thresholdMin,
      },
    });

    if (!result.deduplicated) {
      await triggerEscalation(rule, result.id);
    }
  }
}

// ── Job Failed > N times in T minutes ──
async function evaluateJobFailed(rule: any): Promise<void> {
  const threshold = rule.params?.failure_count ?? 3;
  const windowMin = rule.params?.window_minutes ?? 30;
  const jobType = rule.params?.job_type; // optional filter

  let jobTypeFilter = '';
  const params: any[] = [rule.org_id, windowMin, threshold];
  if (jobType) {
    jobTypeFilter = 'AND j.job_type = $4';
    params.push(jobType);
  }

  const { rows } = await query(
    `SELECT j.agent_id, a.hostname, COUNT(*) AS fail_count
     FROM jobs j
     JOIN agents a ON a.id = j.agent_id
     WHERE j.org_id = $1
       AND j.status = 'failed'
       AND j.completed_at >= NOW() - ($2 || ' minutes')::INTERVAL
       ${jobTypeFilter}
     GROUP BY j.agent_id, a.hostname
     HAVING COUNT(*) >= $3
     LIMIT 100`,
    params
  );

  for (const row of rows) {
    const fingerprint = `job_failed:${row.agent_id}:${jobType ?? 'any'}`;
    const result = await alertSvc.createAlertEvent({
      org_id: rule.org_id,
      rule_id: rule.id,
      rule_name: rule.name,
      entity_type: 'job',
      entity_id: row.agent_id,
      fingerprint,
      severity: rule.severity,
      title: `${row.fail_count} job failures on ${row.hostname}`,
      details: {
        agent_id: row.agent_id,
        hostname: row.hostname,
        failure_count: parseInt(row.fail_count),
        window_minutes: windowMin,
        job_type: jobType ?? 'any',
      },
    });

    if (!result.deduplicated) {
      await triggerEscalation(rule, result.id);
    }
  }
}

// ── EDR Critical Detection ──
async function evaluateEdrCritical(rule: any): Promise<void> {
  // Find critical detections not yet linked to an alert event
  const { rows: detections } = await query(
    `SELECT d.id, d.agent_id, d.rule_name, d.severity, a.hostname
     FROM detections d
     JOIN agents a ON a.id = d.agent_id
     WHERE d.org_id = $1
       AND d.severity = 'critical'
       AND d.status = 'open'
       AND d.created_at >= NOW() - INTERVAL '5 minutes'
     LIMIT 50`,
    [rule.org_id]
  );

  for (const det of detections) {
    const fingerprint = `edr_critical:${det.id}`;
    const result = await alertSvc.createAlertEvent({
      org_id: rule.org_id,
      rule_id: rule.id,
      rule_name: rule.name,
      entity_type: 'detection',
      entity_id: det.id,
      fingerprint,
      severity: 'critical',
      title: `Critical EDR detection: ${det.rule_name} on ${det.hostname}`,
      details: {
        detection_id: det.id,
        agent_id: det.agent_id,
        hostname: det.hostname,
        rule_name: det.rule_name,
      },
    });

    if (!result.deduplicated) {
      await triggerEscalation(rule, result.id);
    }
  }
}

// ── Tamper Detected ──
async function evaluateTamperDetected(rule: any): Promise<void> {
  const { rows: events } = await query(
    `SELECT se.id, se.agent_id, se.event_type, a.hostname
     FROM security_events se
     JOIN agents a ON a.id = se.agent_id
     WHERE se.org_id = $1
       AND se.event_type IN ('tamper_detected','agent_uninstall','service_stopped')
       AND se.created_at >= NOW() - INTERVAL '5 minutes'
     LIMIT 50`,
    [rule.org_id]
  );

  for (const ev of events) {
    const fingerprint = `tamper:${ev.agent_id}:${ev.event_type}`;
    const result = await alertSvc.createAlertEvent({
      org_id: rule.org_id,
      rule_id: rule.id,
      rule_name: rule.name,
      entity_type: 'security_event',
      entity_id: ev.id,
      fingerprint,
      severity: 'critical',
      title: `Tamper detected: ${ev.event_type} on ${ev.hostname}`,
      details: {
        agent_id: ev.agent_id,
        hostname: ev.hostname,
        event_type: ev.event_type,
      },
    });

    if (!result.deduplicated) {
      await triggerEscalation(rule, result.id);
    }
  }
}

// ── Metric Threshold (CPU/RAM/etc) ──
async function evaluateMetricThreshold(rule: any): Promise<void> {
  // Stub: requires metrics table which may not exist yet
  // In production, query agent metrics and compare against threshold
  console.log('[alert-engine] metric_threshold rule evaluation — stub');
}

// ════════════════════════════════════════════
// ESCALATION
// ════════════════════════════════════════════

async function triggerEscalation(rule: any, eventId: string): Promise<void> {
  const escalations = await alertSvc.getEscalationsForRule(rule.id);
  if (!escalations.length) {
    // No escalation defined — send basic notification via all configured channels
    await sendDefaultNotification(rule, eventId);
    return;
  }

  // Start at step 1
  const step1 = escalations.find((e: any) => e.step === 1);
  if (step1) {
    await executeEscalationStep(rule, eventId, step1);
    await alertSvc.advanceEscalation(eventId, 1);
  }
}

async function executeEscalationStep(rule: any, eventId: string, escalation: any): Promise<void> {
  const event = await alertSvc.getAlertEventById(rule.org_id, eventId);
  if (!event) return;

  const channels: string[] = typeof escalation.channels === 'string'
    ? JSON.parse(escalation.channels) : escalation.channels;

  for (const channel of channels) {
    await notifier.dispatch({
      event_id: eventId,
      escalation_id: escalation.id,
      channel,
      title: event.title,
      severity: event.severity,
      body: `Alert: ${event.title}\nSeverity: ${event.severity}\nEntity: ${event.entity_type} ${event.entity_id ?? ''}\n\n${JSON.stringify(event.details, null, 2)}`,
      org_id: rule.org_id,
    });
  }
}

async function sendDefaultNotification(rule: any, eventId: string): Promise<void> {
  const event = await alertSvc.getAlertEventById(rule.org_id, eventId);
  if (!event) return;

  // Try all configured integration types
  for (const channel of ['teams', 'email', 'pagerduty', 'opsgenie', 'webhook']) {
    const integrations = await alertSvc.getIntegrationsByType(rule.org_id, channel);
    if (integrations.length > 0) {
      await notifier.dispatch({
        event_id: eventId,
        channel,
        title: event.title,
        severity: event.severity,
        body: `Alert: ${event.title}\nSeverity: ${event.severity}\nEntity: ${event.entity_type} ${event.entity_id ?? ''}`,
        org_id: rule.org_id,
      });
    }
  }
}

// ── Escalation advancement (runs periodically) ──
async function processEscalations(): Promise<void> {
  try {
    // Find open/ack events with escalation that can advance
    const { rows: events } = await query(
      `SELECT e.id AS event_id, e.org_id, e.rule_id, e.escalation_step, e.last_escalated_at
       FROM alert_events e
       WHERE e.status IN ('open','acknowledged')
         AND e.rule_id IS NOT NULL
         AND e.last_escalated_at IS NOT NULL
       LIMIT 200`
    );

    for (const ev of events) {
      try {
        const escalations = await alertSvc.getEscalationsForRule(ev.rule_id);
        const currentStep = ev.escalation_step;
        const nextEsc = escalations.find((esc: any) => esc.step === currentStep + 1);
        if (!nextEsc) continue;

        // Check if delay has elapsed
        const lastEscAt = new Date(ev.last_escalated_at).getTime();
        const delaySec = nextEsc.delay_sec || 0;
        if (Date.now() - lastEscAt < delaySec * 1000) continue;

        // Get the rule for context
        const rule = await alertSvc.getRuleById(ev.org_id, ev.rule_id);
        if (!rule) continue;

        await executeEscalationStep(rule, ev.event_id, nextEsc);
        await alertSvc.advanceEscalation(ev.event_id, nextEsc.step);
        console.log(`[alert-engine] Escalated event ${ev.event_id} to step ${nextEsc.step}`);
      } catch (err: any) {
        console.error(`[alert-engine] Escalation error for event ${ev.event_id}:`, err.message);
      }
    }
  } catch (err: any) {
    console.error('[alert-engine] Escalation processing failed:', err.message);
  }
}

// ════════════════════════════════════════════
// SCOPE FILTER BUILDER
// ════════════════════════════════════════════

function buildScopeFilter(rule: any, alias: string): string {
  if (rule.scope_type === 'company' && rule.scope_value) {
    return `AND ${alias}.company_id = '${rule.scope_value}'`;
  }
  if (rule.scope_type === 'folder' && rule.scope_value) {
    return `AND EXISTS (SELECT 1 FROM agent_folder_membership afm WHERE afm.agent_id = ${alias}.id AND afm.folder_id = '${rule.scope_value}')`;
  }
  if (rule.scope_type === 'tag' && rule.scope_value) {
    return `AND '${rule.scope_value}' = ANY(${alias}.tags)`;
  }
  return '';
}

// ════════════════════════════════════════════
// LIFECYCLE (start/stop)
// ════════════════════════════════════════════

export function startAlertEngine(): void {
  console.log('[alert-engine] Starting alert engine...');

  // Evaluate rules every 60 seconds
  engineTimer = setInterval(() => {
    evaluateRules().catch(err => console.error('[alert-engine]', err));
  }, 60_000);

  // Process escalations every 30 seconds
  escalationTimer = setInterval(() => {
    processEscalations().catch(err => console.error('[alert-engine]', err));
  }, 30_000);

  // Re-open expired snoozes every 60 seconds
  snoozeTimer = setInterval(() => {
    alertSvc.reopenExpiredSnoozes().catch(err => console.error('[alert-engine]', err));
  }, 60_000);

  // Run initial evaluation after 5s startup delay
  setTimeout(() => {
    evaluateRules().catch(err => console.error('[alert-engine]', err));
  }, 5_000);

  console.log('[alert-engine] Alert engine started (eval=60s, escalation=30s, snooze=60s)');
}

export function stopAlertEngine(): void {
  if (engineTimer) { clearInterval(engineTimer); engineTimer = null; }
  if (escalationTimer) { clearInterval(escalationTimer); escalationTimer = null; }
  if (snoozeTimer) { clearInterval(snoozeTimer); snoozeTimer = null; }
  console.log('[alert-engine] Alert engine stopped');
}
