'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Plus, X, Save, Trash2, Settings2, Zap, Bell, ArrowLeft,
  Server, AlertTriangle, ShieldAlert, Activity, Cpu,
} from 'lucide-react';

const ruleTypeInfo: Record<string, { label: string; icon: any; description: string }> = {
  agent_offline: { label: 'Agent Offline', icon: Server, description: 'Triggers when an agent has not sent a heartbeat for X minutes.' },
  job_failed: { label: 'Job Failures', icon: AlertTriangle, description: 'Triggers when jobs fail N times within a time window.' },
  edr_critical: { label: 'EDR Critical', icon: ShieldAlert, description: 'Triggers immediately on critical EDR detections.' },
  tamper_detected: { label: 'Tamper Detected', icon: Zap, description: 'Triggers when agent tampering or unauthorized removal is detected.' },
  metric_threshold: { label: 'Metric Threshold', icon: Cpu, description: 'Triggers when metrics exceed configured thresholds.' },
};

const channelOptions = ['email', 'teams', 'pagerduty', 'opsgenie', 'webhook'];

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
      .then(r => { setRules(r.data); })
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

  const openCreate = () => { resetForm(); setShowForm(true); };

  const openEdit = (rule: any) => {
    setEditingRule(rule);
    setName(rule.name);
    setDescription(rule.description ?? '');
    setRuleType(rule.rule_type);
    setScopeType(rule.scope_type);
    setScopeValue(rule.scope_value ?? '');
    setSeverity(rule.severity);
    setCooldown(rule.cooldown_sec);
    setIsEnabled(rule.is_enabled);
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
    if (editingRule) {
      await api.alerts.rules.update(editingRule.id, payload);
    } else {
      await api.alerts.rules.create(payload);
    }
    setShowForm(false);
    resetForm();
    loadRules();
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this rule?')) return;
    await api.alerts.rules.delete(id);
    loadRules();
  };

  const handleToggle = async (rule: any) => {
    await api.alerts.rules.update(rule.id, { is_enabled: !rule.is_enabled });
    loadRules();
  };

  const addEscalation = () => {
    setEscalations([...escalations, {
      step: escalations.length + 1, delay_sec: 300,
      target_type: 'role', target_role: 'org_admin', channels: ['email'],
    }]);
  };

  const removeEscalation = (idx: number) => {
    setEscalations(escalations.filter((_, i) => i !== idx));
  };

  const updateEscalation = (idx: number, field: string, value: any) => {
    const updated = [...escalations];
    updated[idx] = { ...updated[idx], [field]: value };
    setEscalations(updated);
  };

  const updateParam = (key: string, value: any) => {
    setParams({ ...params, [key]: value });
  };

  const saveIntegration = async () => {
    try {
      const config = JSON.parse(integConfig);
      await api.alerts.integrations.create({ type: integType, name: integName, config });
      setIntegName(''); setIntegConfig('{}');
      loadIntegrations();
    } catch { alert('Invalid JSON config'); }
  };

  const deleteIntegration = async (id: string) => {
    await api.alerts.integrations.delete(id);
    loadIntegrations();
  };

  const testChannel = async (channel: string) => {
    const result = await api.alerts.test(channel);
    alert(result.ok ? `Test ${channel} sent successfully!` : `Test failed: ${result.error}`);
  };

  // Render parameter fields based on rule type
  const renderParamFields = () => {
    switch (ruleType) {
      case 'agent_offline':
        return (
          <div>
            <label className="text-xs text-reap3r-muted">Threshold (minutes)</label>
            <input type="number" value={params.threshold_minutes ?? 10} min={1} max={1440}
              onChange={e => updateParam('threshold_minutes', Number(e.target.value))}
              className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
          </div>
        );
      case 'job_failed':
        return (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-reap3r-muted">Failure Count Threshold</label>
              <input type="number" value={params.failure_count ?? 3} min={1}
                onChange={e => updateParam('failure_count', Number(e.target.value))}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
            </div>
            <div>
              <label className="text-xs text-reap3r-muted">Window (minutes)</label>
              <input type="number" value={params.window_minutes ?? 30} min={1}
                onChange={e => updateParam('window_minutes', Number(e.target.value))}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
            </div>
            <div className="col-span-2">
              <label className="text-xs text-reap3r-muted">Job Type (optional)</label>
              <input type="text" value={params.job_type ?? ''} placeholder="e.g. run_script"
                onChange={e => updateParam('job_type', e.target.value || undefined)}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
            </div>
          </div>
        );
      case 'metric_threshold':
        return (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-reap3r-muted">Metric</label>
              <select value={params.metric ?? 'cpu_percent'}
                onChange={e => updateParam('metric', e.target.value)}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1">
                <option value="cpu_percent">CPU %</option>
                <option value="mem_percent">Memory %</option>
                <option value="disk_percent">Disk %</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-reap3r-muted">Threshold (%)</label>
              <input type="number" value={params.threshold ?? 95} min={1} max={100}
                onChange={e => updateParam('threshold', Number(e.target.value))}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
            </div>
            <div>
              <label className="text-xs text-reap3r-muted">Duration (minutes)</label>
              <input type="number" value={params.duration_minutes ?? 10} min={1}
                onChange={e => updateParam('duration_minutes', Number(e.target.value))}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <>
      <TopBar
        title="Alert Rules & Integrations"
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => window.location.href = '/alerting'}>
              <ArrowLeft className="w-3 h-3 mr-1" /> Back to Alerts
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setShowIntegrations(!showIntegrations)}>
              <Settings2 className="w-3 h-3 mr-1" /> Integrations
            </Button>
            <Button size="sm" onClick={openCreate}>
              <Plus className="w-3 h-3 mr-1" /> New Rule
            </Button>
          </div>
        }
      />

      <div className="p-6 space-y-6">
        {/* Integrations Panel */}
        {showIntegrations && (
          <Card>
            <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
              <Settings2 className="w-4 h-4 text-reap3r-accent" /> Notification Integrations
            </h3>

            {/* Existing integrations */}
            {integrations.length > 0 && (
              <div className="space-y-2 mb-4">
                {integrations.map(integ => (
                  <div key={integ.id} className="flex items-center justify-between bg-reap3r-bg p-3 rounded-lg border border-reap3r-border">
                    <div>
                      <span className="text-sm font-medium text-reap3r-text">{integ.name}</span>
                      <span className="ml-2 inline-block"><Badge>{integ.type}</Badge></span>
                      {!integ.is_enabled && <span className="ml-1 inline-block"><Badge variant="danger">Disabled</Badge></span>}
                    </div>
                    <div className="flex gap-1">
                      <Button size="sm" variant="secondary" onClick={() => testChannel(integ.type)}>Test</Button>
                      <Button size="sm" variant="danger" onClick={() => deleteIntegration(integ.id)}>
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Add integration form */}
            <div className="grid grid-cols-3 gap-3">
              <select value={integType} onChange={e => setIntegType(e.target.value)}
                className="bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text">
                {channelOptions.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <input value={integName} onChange={e => setIntegName(e.target.value)}
                placeholder="Integration name"
                className="bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text" />
              <Button size="sm" onClick={saveIntegration} disabled={!integName}>
                <Plus className="w-3 h-3 mr-1" /> Add
              </Button>
            </div>
            <textarea value={integConfig} onChange={e => setIntegConfig(e.target.value)} rows={3}
              placeholder='{"webhook_url":"https://..."}' 
              className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-xs text-reap3r-text font-mono mt-2 resize-none" />
            <p className="text-xs text-reap3r-muted mt-1">
              Teams: {`{"webhook_url":"..."}`} · PagerDuty: {`{"routing_key":"..."}`} · Opsgenie: {`{"api_key":"..."}`} · Email: {`{"host":"smtp.example.com","from":"alerts@..."}`}
            </p>
          </Card>
        )}

        {/* Rule creation/edit form */}
        {showForm && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text">
                {editingRule ? 'Edit Rule' : 'Create Alert Rule'}
              </h3>
              <button onClick={() => { setShowForm(false); resetForm(); }} className="text-reap3r-muted hover:text-reap3r-text">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Rule type picker */}
              <div>
                <label className="text-xs text-reap3r-muted mb-2 block">Rule Type</label>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                  {Object.entries(ruleTypeInfo).map(([key, info]) => (
                    <button key={key} onClick={() => {
                      setRuleType(key);
                      if (key === 'agent_offline') setParams({ threshold_minutes: 10 });
                      else if (key === 'job_failed') setParams({ failure_count: 3, window_minutes: 30 });
                      else setParams({});
                    }}
                      className={`flex flex-col items-center gap-1 p-3 rounded-lg border text-xs transition-colors ${ruleType === key ? 'border-reap3r-accent bg-reap3r-accent/10 text-reap3r-accent' : 'border-reap3r-border text-reap3r-muted hover:text-reap3r-text'}`}>
                      <info.icon className="w-5 h-5" />
                      {info.label}
                    </button>
                  ))}
                </div>
                <p className="text-xs text-reap3r-muted mt-1">{ruleTypeInfo[ruleType]?.description}</p>
              </div>

              {/* Name & Description */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-reap3r-muted">Name</label>
                  <input value={name} onChange={e => setName(e.target.value)} placeholder="Rule name"
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
                </div>
                <div>
                  <label className="text-xs text-reap3r-muted">Severity</label>
                  <select value={severity} onChange={e => setSeverity(e.target.value)}
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1">
                    {['info', 'low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs text-reap3r-muted">Description</label>
                <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
                  className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1 resize-none" />
              </div>

              {/* Scope */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-reap3r-muted">Scope</label>
                  <select value={scopeType} onChange={e => setScopeType(e.target.value)}
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1">
                    <option value="all">All agents</option>
                    <option value="company">By Company</option>
                    <option value="folder">By Folder</option>
                    <option value="tag">By Tag</option>
                  </select>
                </div>
                {scopeType !== 'all' && (
                  <div>
                    <label className="text-xs text-reap3r-muted">{scopeType === 'tag' ? 'Tag' : `${scopeType} ID`}</label>
                    <input value={scopeValue} onChange={e => setScopeValue(e.target.value)}
                      placeholder={scopeType === 'tag' ? 'production' : 'UUID'}
                      className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
                  </div>
                )}
              </div>

              {/* Rule-specific params */}
              {renderParamFields()}

              {/* Cooldown */}
              <div>
                <label className="text-xs text-reap3r-muted">Cooldown / Dedup (seconds)</label>
                <input type="number" value={cooldown} min={0} max={86400}
                  onChange={e => setCooldown(Number(e.target.value))}
                  className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1" />
              </div>

              {/* Escalation chain */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-xs text-reap3r-muted">Escalation Chain</label>
                  <Button size="sm" variant="secondary" onClick={addEscalation}>
                    <Plus className="w-3 h-3 mr-1" /> Add Step
                  </Button>
                </div>
                <div className="space-y-3">
                  {escalations.map((esc, idx) => (
                    <div key={idx} className="flex items-start gap-2 bg-reap3r-bg p-3 rounded-lg border border-reap3r-border">
                      <span className="text-xs text-reap3r-accent font-bold mt-2">N{idx + 1}</span>
                      <div className="flex-1 grid grid-cols-4 gap-2 text-xs">
                        <div>
                          <label className="text-reap3r-muted">Delay (sec)</label>
                          <input type="number" value={esc.delay_sec} min={0}
                            onChange={e => updateEscalation(idx, 'delay_sec', Number(e.target.value))}
                            className="w-full bg-reap3r-surface border border-reap3r-border rounded px-2 py-1.5 text-reap3r-text mt-0.5" />
                        </div>
                        <div>
                          <label className="text-reap3r-muted">Target</label>
                          <select value={esc.target_type}
                            onChange={e => updateEscalation(idx, 'target_type', e.target.value)}
                            className="w-full bg-reap3r-surface border border-reap3r-border rounded px-2 py-1.5 text-reap3r-text mt-0.5">
                            <option value="role">Role</option>
                            <option value="team">Team</option>
                            <option value="user">User</option>
                          </select>
                        </div>
                        <div>
                          <label className="text-reap3r-muted">{esc.target_type === 'role' ? 'Role' : 'ID'}</label>
                          <input value={esc.target_type === 'role' ? (esc.target_role ?? '') : (esc.target_id ?? '')}
                            onChange={e => updateEscalation(idx, esc.target_type === 'role' ? 'target_role' : 'target_id', e.target.value)}
                            placeholder={esc.target_type === 'role' ? 'org_admin' : 'UUID'}
                            className="w-full bg-reap3r-surface border border-reap3r-border rounded px-2 py-1.5 text-reap3r-text mt-0.5" />
                        </div>
                        <div>
                          <label className="text-reap3r-muted">Channels</label>
                          <div className="flex flex-wrap gap-1 mt-0.5">
                            {channelOptions.map(ch => (
                              <button key={ch}
                                onClick={() => {
                                  const channels = esc.channels.includes(ch)
                                    ? esc.channels.filter((c: string) => c !== ch)
                                    : [...esc.channels, ch];
                                  updateEscalation(idx, 'channels', channels);
                                }}
                                className={`px-1.5 py-0.5 rounded text-[10px] ${esc.channels.includes(ch) ? 'bg-reap3r-accent/20 text-reap3r-accent' : 'bg-reap3r-surface text-reap3r-muted'}`}>
                                {ch}
                              </button>
                            ))}
                          </div>
                        </div>
                      </div>
                      {escalations.length > 1 && (
                        <button onClick={() => removeEscalation(idx)} className="text-reap3r-muted hover:text-red-400 mt-2">
                          <X className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Enabled toggle */}
              <label className="flex items-center gap-2 text-sm text-reap3r-text cursor-pointer">
                <input type="checkbox" checked={isEnabled} onChange={e => setIsEnabled(e.target.checked)}
                  className="rounded border-reap3r-border" />
                Enable rule immediately
              </label>

              {/* Save */}
              <div className="flex justify-end gap-2">
                <Button variant="secondary" onClick={() => { setShowForm(false); resetForm(); }}>Cancel</Button>
                <Button onClick={handleSave} disabled={!name}>
                  <Save className="w-3 h-3 mr-1" /> {editingRule ? 'Update' : 'Create'} Rule
                </Button>
              </div>
            </div>
          </Card>
        )}

        {/* Rules list */}
        {loading ? (
          <div className="text-reap3r-muted text-sm">Loading rules...</div>
        ) : rules.length === 0 && !showForm ? (
          <EmptyState
            icon={<Bell className="w-8 h-8" />}
            title="No alert rules"
            description="Create your first alert rule to start monitoring your infrastructure."
          />
        ) : (
          <div className="space-y-2">
            {rules.map(rule => {
              const info = ruleTypeInfo[rule.rule_type];
              const Icon = info?.icon ?? Bell;
              return (
                <Card key={rule.id} className="flex items-center justify-between !py-3">
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${rule.is_enabled ? 'bg-reap3r-accent/10' : 'bg-reap3r-bg'}`}>
                      <Icon className={`w-4 h-4 ${rule.is_enabled ? 'text-reap3r-accent' : 'text-reap3r-muted'}`} />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-reap3r-text">{rule.name}</p>
                      <p className="text-xs text-reap3r-muted">
                        {info?.label ?? rule.rule_type} · scope: {rule.scope_type}
                        {rule.scope_value ? ` (${rule.scope_value})` : ''}
                        {' · '}{rule.escalations?.length ?? 0} escalation step(s)
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={severityColor(rule.severity) as any}>{rule.severity}</Badge>
                    <Badge variant={rule.is_enabled ? 'success' : 'default'}>
                      {rule.is_enabled ? 'Active' : 'Disabled'}
                    </Badge>
                    <Button size="sm" variant="secondary" onClick={() => handleToggle(rule)}>
                      {rule.is_enabled ? 'Disable' : 'Enable'}
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => openEdit(rule)}>Edit</Button>
                    <Button size="sm" variant="danger" onClick={() => handleDelete(rule.id)}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}

function severityColor(s: string) {
  switch (s) {
    case 'critical': return 'danger';
    case 'high': return 'danger';
    case 'medium': return 'warning';
    case 'low': return 'default';
    default: return 'default';
  }
}
