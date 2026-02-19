'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Plus, X, Trash2, Settings2, Zap, Bell, ArrowLeft,
  Server, AlertTriangle, ShieldAlert, Cpu, Check, Send,
  Mail, MessageSquare, Webhook,
} from 'lucide-react';

const ruleTypeInfo: Record<string, { label: string; icon: any; description: string }> = {
  agent_offline:    { label: 'Agent Offline',    icon: Server,      description: 'Triggers when an agent has not sent a heartbeat for X minutes.' },
  job_failed:       { label: 'Job Failures',      icon: AlertTriangle, description: 'Triggers when jobs fail N times within a time window.' },
  edr_critical:     { label: 'EDR Critical',      icon: ShieldAlert, description: 'Triggers immediately on critical EDR detections.' },
  tamper_detected:  { label: 'Tamper Detected',   icon: Zap,         description: 'Triggers when agent tampering or unauthorized removal is detected.' },
  metric_threshold: { label: 'Metric Threshold',  icon: Cpu,         description: 'Triggers when metrics exceed configured thresholds.' },
};

const channelOptions = ['email', 'teams', 'pagerduty', 'opsgenie', 'webhook'];

const severityVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'default';
};

const inputCls = 'w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20';
const selectCls = 'w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20';

export default function RulesPage() {
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingRule, setEditingRule] = useState<any>(null);
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [showIntegrations, setShowIntegrations] = useState(false);

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [ruleType, setRuleType] = useState('agent_offline');
  const [scopeType, setScopeType] = useState('all');
  const [scopeValue, setScopeValue] = useState('');
  const [severity, setSeverity] = useState('high');
  const [cooldown, setCooldown] = useState(300);
  const [isEnabled, setIsEnabled] = useState(true);
  const [params, setParams] = useState<Record<string, any>>({ threshold_minutes: 10 });
  const [escalations, setEscalations] = useState<any[]>([
    { step: 1, delay_sec: 0, target_type: 'role', target_role: 'org_admin', channels: ['email'] },
  ]);

  // Integration form
  const [integType, setIntegType] = useState('teams');
  const [integName, setIntegName] = useState('');
  const [integConfig, setIntegConfig] = useState('{}');

  const loadRules = () => {
    setLoading(true);
    api.alerts.rules.list()
      .then(r => setRules(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  const loadIntegrations = () => {
    api.alerts.integrations.list()
      .then(r => setIntegrations(r.data))
      .catch(() => {});
  };

  useEffect(() => { loadRules(); loadIntegrations(); }, []);

  const resetForm = () => {
    setName(''); setDescription(''); setRuleType('agent_offline');
    setScopeType('all'); setScopeValue(''); setSeverity('high');
    setCooldown(300); setIsEnabled(true);
    setParams({ threshold_minutes: 10 });
    setEscalations([{ step: 1, delay_sec: 0, target_type: 'role', target_role: 'org_admin', channels: ['email'] }]);
    setEditingRule(null);
  };

  const openEdit = (rule: any) => {
    setEditingRule(rule);
    setName(rule.name); setDescription(rule.description ?? '');
    setRuleType(rule.rule_type); setScopeType(rule.scope_type);
    setScopeValue(rule.scope_value ?? ''); setSeverity(rule.severity);
    setCooldown(rule.cooldown_sec); setIsEnabled(rule.is_enabled);
    setParams(rule.params ?? {});
    setEscalations(rule.escalations?.length ? rule.escalations.map((e: any) => ({
      step: e.step, delay_sec: e.delay_sec, target_type: e.target_type,
      target_id: e.target_id, target_role: e.target_role,
      channels: typeof e.channels === 'string' ? JSON.parse(e.channels) : e.channels,
    })) : [{ step: 1, delay_sec: 0, target_type: 'role', target_role: 'org_admin', channels: ['email'] }]);
    setShowForm(true);
  };

  const handleSave = async () => {
    const payload = {
      name, description: description || undefined, rule_type: ruleType,
      scope_type: scopeType, scope_value: scopeValue || undefined,
      params, severity, cooldown_sec: cooldown, is_enabled: isEnabled,
      escalations: escalations.map((e, i) => ({ ...e, step: i + 1 })),
    };
    if (editingRule) await api.alerts.rules.update(editingRule.id, payload);
    else await api.alerts.rules.create(payload);
    setShowForm(false); resetForm(); loadRules();
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this rule?')) return;
    await api.alerts.rules.delete(id); loadRules();
  };

  const handleToggle = async (rule: any) => {
    await api.alerts.rules.update(rule.id, { is_enabled: !rule.is_enabled }); loadRules();
  };

  const addEscalation = () => setEscalations([...escalations, {
    step: escalations.length + 1, delay_sec: 300,
    target_type: 'role', target_role: 'org_admin', channels: ['email'],
  }]);

  const removeEscalation = (idx: number) => setEscalations(escalations.filter((_, i) => i !== idx));

  const updateEscalation = (idx: number, field: string, value: any) => {
    const updated = [...escalations];
    updated[idx] = { ...updated[idx], [field]: value };
    setEscalations(updated);
  };

  const updateParam = (key: string, value: any) => setParams({ ...params, [key]: value });

  const saveIntegration = async () => {
    try {
      const config = JSON.parse(integConfig);
      await api.alerts.integrations.create({ type: integType, name: integName, config });
      setIntegName(''); setIntegConfig('{}'); loadIntegrations();
    } catch { alert('Invalid JSON config'); }
  };

  const deleteIntegration = async (id: string) => {
    await api.alerts.integrations.delete(id); loadIntegrations();
  };

  const testChannel = async (channel: string) => {
    const result = await api.alerts.test(channel);
    alert(result.ok ? `Test ${channel} sent!` : `Failed: ${result.error}`);
  };

  const renderParamFields = () => {
    switch (ruleType) {
      case 'agent_offline':
        return (
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Threshold (minutes)</label>
            <input type="number" value={params.threshold_minutes ?? 10} min={1} max={1440}
              onChange={e => updateParam('threshold_minutes', Number(e.target.value))} className={inputCls} />
          </div>
        );
      case 'job_failed':
        return (
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Failure Count</label>
              <input type="number" value={params.failure_count ?? 3} min={1}
                onChange={e => updateParam('failure_count', Number(e.target.value))} className={inputCls} />
            </div>
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Window (min)</label>
              <input type="number" value={params.window_minutes ?? 30} min={1}
                onChange={e => updateParam('window_minutes', Number(e.target.value))} className={inputCls} />
            </div>
          </div>
        );
      case 'metric_threshold':
        return (
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Metric</label>
              <select value={params.metric ?? 'cpu_percent'} onChange={e => updateParam('metric', e.target.value)} className={selectCls}>
                <option value="cpu_percent">CPU %</option>
                <option value="mem_percent">Memory %</option>
                <option value="disk_percent">Disk %</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Threshold (%)</label>
              <input type="number" value={params.threshold ?? 95} min={1} max={100}
                onChange={e => updateParam('threshold', Number(e.target.value))} className={inputCls} />
            </div>
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Duration (min)</label>
              <input type="number" value={params.duration_minutes ?? 10} min={1}
                onChange={e => updateParam('duration_minutes', Number(e.target.value))} className={inputCls} />
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  const typeIcons: Record<string, any> = {
    teams: <MessageSquare style={{ width: '13px', height: '13px', color: '#a78bfa' }} />,
    email: <Mail style={{ width: '13px', height: '13px', color: '#60a5fa' }} />,
    webhook: <Webhook style={{ width: '13px', height: '13px', color: '#34d399' }} />,
    pagerduty: <Bell style={{ width: '13px', height: '13px', color: '#fbbf24' }} />,
    opsgenie: <Bell style={{ width: '13px', height: '13px', color: '#fb923c' }} />,
  };

  return (
    <>
      <TopBar
        title="Alert Rules"
        actions={
          <div className="flex gap-2">
            <Link href="/alerting">
              <Button size="sm" variant="secondary">
                <ArrowLeft style={{ width: '11px', height: '11px', marginRight: '4px' }} />Alerts
              </Button>
            </Link>
            <Button size="sm" variant="secondary" onClick={() => setShowIntegrations(true)}>
              <Settings2 style={{ width: '11px', height: '11px', marginRight: '4px' }} />Integrations
            </Button>
            <Button size="sm" onClick={() => { resetForm(); setShowForm(true); }}>
              <Plus style={{ width: '11px', height: '11px', marginRight: '4px' }} />New Rule
            </Button>
          </div>
        }
      />

      <div className="p-6 space-y-4 animate-fade-in">
        {/* Rules list */}
        {loading ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}
          </div>
        ) : rules.length === 0 ? (
          <EmptyState
            icon={<Bell style={{ width: '28px', height: '28px' }} />}
            title="No alert rules"
            description="Create your first alert rule to monitor your infrastructure."
          />
        ) : (
          <div className="space-y-2">
            {rules.map(rule => {
              const info = ruleTypeInfo[rule.rule_type];
              const Icon = info?.icon ?? Bell;
              return (
                <div key={rule.id} className="bg-reap3r-card border border-reap3r-border rounded-xl px-5 py-3.5 flex items-center justify-between gap-4 hover:border-reap3r-border-light transition-all">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${rule.is_enabled ? 'bg-white/6 border border-white/10' : 'bg-reap3r-surface border border-reap3r-border'}`}>
                      <Icon style={{ width: '16px', height: '16px', color: rule.is_enabled ? '#fff' : '#5c5c5c' }} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-[12px] font-semibold text-white truncate">{rule.name}</p>
                      <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">
                        {info?.label ?? rule.rule_type} · scope: {rule.scope_type}
                        {rule.scope_value ? ` (${rule.scope_value.slice(0, 8)})` : ''}
                        {' · '}{rule.escalations?.length ?? 0} escalation step(s)
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge variant={severityVariant(rule.severity)}>{rule.severity}</Badge>
                    <Badge variant={rule.is_enabled ? 'success' : 'default'}>{rule.is_enabled ? 'Active' : 'Disabled'}</Badge>
                    <Button size="sm" variant="secondary" onClick={() => handleToggle(rule)}>
                      {rule.is_enabled ? 'Disable' : 'Enable'}
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => openEdit(rule)}>Edit</Button>
                    <Button size="sm" variant="danger" onClick={() => handleDelete(rule.id)}>
                      <Trash2 style={{ width: '11px', height: '11px' }} />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Rule form modal */}
      <Modal open={showForm} onClose={() => { setShowForm(false); resetForm(); }} title={editingRule ? 'Edit Rule' : 'Create Alert Rule'}>
        <div className="space-y-4">
          {/* Rule type picker */}
          <div className="space-y-2">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Rule Type</label>
            <div className="grid grid-cols-5 gap-2">
              {Object.entries(ruleTypeInfo).map(([key, info]) => (
                <button key={key} onClick={() => {
                  setRuleType(key);
                  if (key === 'agent_offline') setParams({ threshold_minutes: 10 });
                  else if (key === 'job_failed') setParams({ failure_count: 3, window_minutes: 30 });
                  else setParams({});
                }}
                  className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border text-[10px] font-semibold uppercase tracking-[0.06em] transition-all ${
                    ruleType === key ? 'bg-white/8 text-white border-white/20' : 'text-reap3r-muted border-reap3r-border hover:text-reap3r-light hover:border-reap3r-border-light'
                  }`}>
                  <info.icon style={{ width: '16px', height: '16px' }} />
                  <span className="text-center leading-tight">{info.label}</span>
                </button>
              ))}
            </div>
            <p className="text-[10px] text-reap3r-muted">{ruleTypeInfo[ruleType]?.description}</p>
          </div>

          {/* Name & Severity */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="Rule name" className={inputCls} />
            </div>
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className={selectCls}>
                {['info', 'low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
              className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-white resize-none placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>

          {/* Scope */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Scope</label>
              <select value={scopeType} onChange={e => setScopeType(e.target.value)} className={selectCls}>
                <option value="all">All agents</option>
                <option value="company">By Company</option>
                <option value="folder">By Folder</option>
                <option value="tag">By Tag</option>
              </select>
            </div>
            {scopeType !== 'all' && (
              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">{scopeType === 'tag' ? 'Tag' : `${scopeType} ID`}</label>
                <input value={scopeValue} onChange={e => setScopeValue(e.target.value)}
                  placeholder={scopeType === 'tag' ? 'production' : 'UUID'} className={inputCls} />
              </div>
            )}
          </div>

          {/* Rule-specific params */}
          {renderParamFields()}

          {/* Cooldown */}
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Cooldown / Dedup (seconds)</label>
            <input type="number" value={cooldown} min={0} max={86400}
              onChange={e => setCooldown(Number(e.target.value))} className={inputCls} />
          </div>

          {/* Escalation chain */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Escalation Chain</label>
              <Button size="sm" variant="secondary" onClick={addEscalation}>
                <Plus style={{ width: '11px', height: '11px', marginRight: '4px' }} />Add Step
              </Button>
            </div>
            <div className="space-y-2">
              {escalations.map((esc, idx) => (
                <div key={idx} className="flex items-start gap-2 bg-reap3r-bg p-3 rounded-xl border border-reap3r-border">
                  <span className="text-[11px] text-white/40 font-black mt-2 w-4 text-center">N{idx + 1}</span>
                  <div className="flex-1 grid grid-cols-4 gap-2 text-xs">
                    <div>
                      <label className="block text-reap3r-muted mb-0.5">Delay (sec)</label>
                      <input type="number" value={esc.delay_sec} min={0}
                        onChange={e => updateEscalation(idx, 'delay_sec', Number(e.target.value))}
                        className="w-full bg-reap3r-surface border border-reap3r-border rounded-lg px-2 py-1.5 text-white text-xs focus:outline-none focus:ring-1 focus:ring-white/20" />
                    </div>
                    <div>
                      <label className="block text-reap3r-muted mb-0.5">Target</label>
                      <select value={esc.target_type} onChange={e => updateEscalation(idx, 'target_type', e.target.value)}
                        className="w-full bg-reap3r-surface border border-reap3r-border rounded-lg px-2 py-1.5 text-white text-xs focus:outline-none">
                        <option value="role">Role</option>
                        <option value="team">Team</option>
                        <option value="user">User</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-reap3r-muted mb-0.5">{esc.target_type === 'role' ? 'Role' : 'ID'}</label>
                      <input value={esc.target_type === 'role' ? (esc.target_role ?? '') : (esc.target_id ?? '')}
                        onChange={e => updateEscalation(idx, esc.target_type === 'role' ? 'target_role' : 'target_id', e.target.value)}
                        placeholder={esc.target_type === 'role' ? 'org_admin' : 'UUID'}
                        className="w-full bg-reap3r-surface border border-reap3r-border rounded-lg px-2 py-1.5 text-white text-xs focus:outline-none focus:ring-1 focus:ring-white/20" />
                    </div>
                    <div>
                      <label className="block text-reap3r-muted mb-0.5">Channels</label>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {channelOptions.map(ch => (
                          <button key={ch}
                            onClick={() => {
                              const channels = esc.channels.includes(ch)
                                ? esc.channels.filter((c: string) => c !== ch)
                                : [...esc.channels, ch];
                              updateEscalation(idx, 'channels', channels);
                            }}
                            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold transition-all ${
                              esc.channels.includes(ch) ? 'bg-white/10 text-white' : 'bg-reap3r-surface text-reap3r-muted hover:text-reap3r-light'
                            }`}>
                            {ch}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                  {escalations.length > 1 && (
                    <button onClick={() => removeEscalation(idx)} className="text-reap3r-muted hover:text-reap3r-danger mt-2 transition-colors">
                      <X style={{ width: '12px', height: '12px' }} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Enabled toggle */}
          <label className="flex items-center gap-2.5 cursor-pointer">
            <div
              onClick={() => setIsEnabled(!isEnabled)}
              className={`w-9 h-5 rounded-full transition-all relative ${isEnabled ? 'bg-white/20' : 'bg-reap3r-border'}`}
            >
              <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${isEnabled ? 'left-4 bg-white' : 'left-0.5 bg-reap3r-muted'}`} />
            </div>
            <span className="text-xs text-white/70">Enable rule immediately</span>
          </label>

          <div className="flex gap-2 justify-end pt-2 border-t border-reap3r-border">
            <Button variant="secondary" onClick={() => { setShowForm(false); resetForm(); }}>Cancel</Button>
            <Button onClick={handleSave} disabled={!name}>
              <Check style={{ width: '11px', height: '11px', marginRight: '4px' }} />{editingRule ? 'Update' : 'Create'} Rule
            </Button>
          </div>
        </div>
      </Modal>

      {/* Integrations modal */}
      <Modal open={showIntegrations} onClose={() => setShowIntegrations(false)} title="Notification Integrations">
        <div className="space-y-4">
          {/* Existing integrations */}
          {integrations.length > 0 && (
            <div className="space-y-2">
              {integrations.map(integ => (
                <div key={integ.id} className="flex items-center justify-between bg-reap3r-bg p-3 rounded-xl border border-reap3r-border">
                  <div className="flex items-center gap-3">
                    {typeIcons[integ.type] ?? <Bell style={{ width: '13px', height: '13px' }} />}
                    <div>
                      <p className="text-[12px] font-semibold text-white">{integ.name}</p>
                      <p className="text-[10px] text-reap3r-muted capitalize">{integ.type}</p>
                    </div>
                  </div>
                  <div className="flex gap-1.5">
                    <Button size="sm" variant="secondary" onClick={() => testChannel(integ.type)}>
                      <Send style={{ width: '11px', height: '11px', marginRight: '4px' }} />Test
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => deleteIntegration(integ.id)}>
                      <Trash2 style={{ width: '11px', height: '11px' }} />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Add integration form */}
          <div className="pt-2 border-t border-reap3r-border space-y-3">
            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Add Integration</p>
            <div className="grid grid-cols-2 gap-2">
              <select value={integType} onChange={e => setIntegType(e.target.value)} className={selectCls}>
                {channelOptions.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <input value={integName} onChange={e => setIntegName(e.target.value)}
                placeholder="Integration name" className={inputCls} />
            </div>
            <textarea value={integConfig} onChange={e => setIntegConfig(e.target.value)} rows={2}
              placeholder='{"webhook_url":"https://..."}'
              className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-xs text-white font-mono resize-none focus:outline-none focus:ring-1 focus:ring-white/20" />
            <p className="text-[10px] text-reap3r-muted">
              Teams: {`{"webhook_url":"..."}`} · PagerDuty: {`{"routing_key":"..."}`} · Opsgenie: {`{"api_key":"..."}`}
            </p>
            <Button size="sm" onClick={saveIntegration} disabled={!integName}>
              <Plus style={{ width: '11px', height: '11px', marginRight: '4px' }} />Add Integration
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
