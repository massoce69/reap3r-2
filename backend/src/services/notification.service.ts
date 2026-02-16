// ─────────────────────────────────────────────
// MASSVISION Reap3r — Notification Dispatcher
// Sends notifications via Teams, Email, PagerDuty, Opsgenie, Webhook
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';
import * as alertSvc from './alerting.service.js';

interface NotifPayload {
  event_id: string;
  escalation_id?: string;
  channel: string;
  recipient?: string;
  title: string;
  severity: string;
  body: string;
  org_id: string;
}

// ── Dispatch a notification through a channel ──
export async function dispatch(payload: NotifPayload): Promise<void> {
  const logId = await alertSvc.createNotificationLog({
    event_id: payload.event_id,
    escalation_id: payload.escalation_id,
    channel: payload.channel,
    recipient: payload.recipient,
    status: 'pending',
  });

  try {
    switch (payload.channel) {
      case 'teams':
        await sendTeams(payload);
        break;
      case 'email':
        await sendEmail(payload);
        break;
      case 'pagerduty':
        await sendPagerDuty(payload);
        break;
      case 'opsgenie':
        await sendOpsgenie(payload);
        break;
      case 'webhook':
        await sendWebhook(payload);
        break;
      default:
        throw new Error(`Unknown notification channel: ${payload.channel}`);
    }
    await alertSvc.updateNotificationStatus(logId, 'sent');
  } catch (err: any) {
    console.error(`[notifier] Failed to send ${payload.channel} notification:`, err.message);
    await alertSvc.updateNotificationStatus(logId, 'failed', err.message);
  }
}

// ── Teams (Incoming Webhook) ──
async function sendTeams(p: NotifPayload): Promise<void> {
  const integrations = await alertSvc.getIntegrationsByType(p.org_id, 'teams');
  if (!integrations.length) {
    console.warn('[notifier] No Teams integration configured');
    return;
  }

  for (const integ of integrations) {
    const webhookUrl = integ.config?.webhook_url;
    if (!webhookUrl) continue;

    const severityColor = p.severity === 'critical' ? 'FF0000'
      : p.severity === 'high' ? 'FF6600'
      : p.severity === 'medium' ? 'FFAA00'
      : '00AA00';

    const card = {
      '@type': 'MessageCard',
      '@context': 'https://schema.org/extensions',
      themeColor: severityColor,
      summary: `[${p.severity.toUpperCase()}] ${p.title}`,
      sections: [{
        activityTitle: `🚨 Reap3r Alert — ${p.severity.toUpperCase()}`,
        activitySubtitle: p.title,
        facts: [
          { name: 'Severity', value: p.severity },
          { name: 'Event ID', value: p.event_id },
        ],
        text: p.body,
        markdown: true,
      }],
    };

    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(card),
    });
    if (!resp.ok) throw new Error(`Teams webhook returned ${resp.status}: ${await resp.text()}`);
  }
}

// ── Email (SMTP stub — production: use nodemailer or SES) ──
async function sendEmail(p: NotifPayload): Promise<void> {
  const integrations = await alertSvc.getIntegrationsByType(p.org_id, 'email');
  if (!integrations.length) {
    // Log only — email not configured
    console.warn('[notifier] No email integration configured, skipping');
    return;
  }

  for (const integ of integrations) {
    const smtpConfig = integ.config;
    // In production, use nodemailer here
    // For now, log the intent
    console.log(`[notifier:email] Would send to ${p.recipient ?? smtpConfig?.to ?? 'default'}: [${p.severity}] ${p.title}`);
    console.log(`[notifier:email] SMTP host: ${smtpConfig?.host ?? 'not set'}, from: ${smtpConfig?.from ?? 'not set'}`);
  }
}

// ── PagerDuty (Events API v2) ──
async function sendPagerDuty(p: NotifPayload): Promise<void> {
  const integrations = await alertSvc.getIntegrationsByType(p.org_id, 'pagerduty');
  if (!integrations.length) {
    console.warn('[notifier] No PagerDuty integration configured');
    return;
  }

  for (const integ of integrations) {
    const routingKey = integ.config?.routing_key;
    if (!routingKey) continue;

    const pdSeverity = p.severity === 'critical' ? 'critical'
      : p.severity === 'high' ? 'error'
      : p.severity === 'medium' ? 'warning'
      : 'info';

    const pdPayload = {
      routing_key: routingKey,
      event_action: 'trigger',
      dedup_key: `reap3r-${p.event_id}`,
      payload: {
        summary: `[Reap3r] ${p.title}`,
        severity: pdSeverity,
        source: 'massvision-reap3r',
        custom_details: { body: p.body, event_id: p.event_id },
      },
    };

    const resp = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pdPayload),
    });
    if (!resp.ok) throw new Error(`PagerDuty returned ${resp.status}: ${await resp.text()}`);
  }
}

// ── Opsgenie (Alert API) ──
async function sendOpsgenie(p: NotifPayload): Promise<void> {
  const integrations = await alertSvc.getIntegrationsByType(p.org_id, 'opsgenie');
  if (!integrations.length) {
    console.warn('[notifier] No Opsgenie integration configured');
    return;
  }

  for (const integ of integrations) {
    const apiKey = integ.config?.api_key;
    const apiUrl = integ.config?.api_url ?? 'https://api.opsgenie.com/v2/alerts';
    if (!apiKey) continue;

    const ogPriority = p.severity === 'critical' ? 'P1'
      : p.severity === 'high' ? 'P2'
      : p.severity === 'medium' ? 'P3'
      : 'P4';

    const ogPayload = {
      message: `[Reap3r] ${p.title}`,
      alias: `reap3r-${p.event_id}`,
      description: p.body,
      priority: ogPriority,
      source: 'massvision-reap3r',
      tags: ['reap3r', p.severity],
      details: { event_id: p.event_id },
    };

    const resp = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `GenieKey ${apiKey}` },
      body: JSON.stringify(ogPayload),
    });
    if (!resp.ok) throw new Error(`Opsgenie returned ${resp.status}: ${await resp.text()}`);
  }
}

// ── Generic Webhook ──
async function sendWebhook(p: NotifPayload): Promise<void> {
  const integrations = await alertSvc.getIntegrationsByType(p.org_id, 'webhook');
  if (!integrations.length) {
    console.warn('[notifier] No webhook integration configured');
    return;
  }

  for (const integ of integrations) {
    const url = integ.config?.url;
    if (!url) continue;

    const body = {
      source: 'massvision-reap3r',
      event_id: p.event_id,
      title: p.title,
      severity: p.severity,
      body: p.body,
      timestamp: new Date().toISOString(),
    };

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (integ.config?.secret) {
      headers['X-Reap3r-Signature'] = integ.config.secret;
    }

    const resp = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!resp.ok) throw new Error(`Webhook returned ${resp.status}`);
  }
}

// ── Test notification ──
export async function sendTestNotification(orgId: string, channel: string): Promise<{ ok: boolean; error?: string }> {
  try {
    await dispatch({
      event_id: '00000000-0000-0000-0000-000000000000',
      channel,
      title: 'Test Alert from Reap3r',
      severity: 'info',
      body: 'This is a test notification. If you see this, the integration is working correctly.',
      org_id: orgId,
    });
    return { ok: true };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}
