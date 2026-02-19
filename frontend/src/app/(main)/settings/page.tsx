'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, Input, EmptyState, Modal, TabBar } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import {
  Globe, Shield, Key, Webhook, Plus, Copy, Eye, EyeOff, Trash2,
  CheckCircle, AlertTriangle, Mail, MessageSquare, Send, Bell, User
} from 'lucide-react';

type Tab = 'organization' | 'api-keys' | 'integrations' | 'profile';

export default function SettingsPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<Tab>('organization');

  const tabs: { key: Tab; label: string }[] = [
    { key: 'organization', label: 'Organization' },
    { key: 'api-keys', label: 'API Keys' },
    { key: 'integrations', label: 'Integrations' },
    { key: 'profile', label: 'Profile' },
  ];

  return (
    <>
      <TopBar title="Settings" />
      <div className="p-6 space-y-4 animate-fade-in">
        <TabBar tabs={tabs} active={tab} onChange={(k) => setTab(k as Tab)} />
        {tab === 'organization' && <OrganizationTab />}
        {tab === 'api-keys' && <ApiKeysTab />}
        {tab === 'integrations' && <IntegrationsTab />}
        {tab === 'profile' && <ProfileTab />}
      </div>
    </>
  );
}

/* ── Organization Tab ── */
function OrganizationTab() {
  const { user } = useAuth();
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
            <Globe className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
          </div>
          <div>
            <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Organization</h3>
            <p className="text-[10px] text-reap3r-muted">Platform configuration and access control</p>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="p-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl">
            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Org ID</p>
            <p className="text-white font-mono text-[11px] mt-1">{user?.org_id}</p>
          </div>
          <div className="p-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl">
            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Your Role</p>
            <div className="mt-1"><Badge variant="accent">{user?.role}</Badge></div>
          </div>
        </div>
      </Card>

      <Card>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
            <Shield className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
          </div>
          <div>
            <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">RBAC Roles</h3>
            <p className="text-[10px] text-reap3r-muted">Role-based access control definitions</p>
          </div>
        </div>
        <div className="space-y-2">
          {[
            { role: 'super_admin', desc: 'Full platform access. Manage orgs, users, agents, policies, settings.' },
            { role: 'org_admin', desc: 'Full org access. Manage users, agents, jobs, policies.' },
            { role: 'operator', desc: 'Run jobs, manage agents, remote shell, view audit logs.' },
            { role: 'soc_analyst', desc: 'EDR events, detections, incidents, response actions, alerting.' },
            { role: 'viewer', desc: 'Read-only access to agents, jobs, audit logs, dashboards.' },
          ].map((r) => (
            <div key={r.role} className="flex items-start gap-3 p-3 bg-reap3r-surface/40 border border-reap3r-border/60 rounded-xl">
              <Badge variant={r.role === user?.role ? 'accent' : 'default'}>{r.role}</Badge>
              <p className="text-[11px] text-reap3r-muted leading-relaxed">{r.desc}</p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

/* ── API Keys Tab ── */
function ApiKeysTab() {
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>(['read']);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api.apiKeys.list().then(r => { setKeys(r.data); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!name) return;
    try {
      const res = await api.apiKeys.create({ name, scopes });
      setNewKey(res.key); setShowCreate(false); setName(''); load();
    } catch (e: any) { alert(e.message); }
  };

  const revoke = async (id: string) => { if (!confirm('Revoke this API key?')) return; await api.apiKeys.revoke(id); load(); };
  const deleteKey = async (id: string) => { if (!confirm('Permanently delete this API key?')) return; await api.apiKeys.delete(id); load(); };
  const copyKey = () => { if (newKey) navigator.clipboard.writeText(newKey); };

  const availableScopes = ['read', 'write', 'admin', 'agents', 'jobs', 'vault', 'edr', 'alerting'];

  return (
    <div className="space-y-4">
      {/* New key banner */}
      {newKey && (
        <div className="px-5 py-4 bg-reap3r-success/6 border border-reap3r-success/20 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold text-reap3r-success uppercase tracking-[0.08em]">New API Key Created</span>
          </div>
          <p className="text-[10px] text-reap3r-muted mb-3">Copy this key now — it won't be shown again.</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-reap3r-surface border border-reap3r-border rounded-lg px-3 py-2 text-[11px] font-mono text-white overflow-x-auto">
              {showKey ? newKey : '•'.repeat(40)}
            </code>
            <button onClick={() => setShowKey(!showKey)} className="p-1.5 text-reap3r-muted hover:text-white rounded-lg transition-all">
              {showKey ? <EyeOff style={{ width: '13px', height: '13px' }} /> : <Eye style={{ width: '13px', height: '13px' }} />}
            </button>
            <Button size="sm" onClick={copyKey}><Copy style={{ width: '10px', height: '10px', marginRight: '4px' }} />Copy</Button>
          </div>
        </div>
      )}

      <div className="flex justify-between items-center">
        <h3 className="text-[11px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">API Keys</h3>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Create Key
        </Button>
      </div>

      {loading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl h-14 animate-pulse" />)}
        </div>
      ) : keys.length === 0 ? (
        <EmptyState icon={<Key style={{ width: '28px', height: '28px' }} />} title="No API keys" description="Create API keys for programmatic access." />
      ) : (
        <div className="space-y-2">
          {keys.map(k => (
            <Card key={k.id} className="flex items-center justify-between !py-3 group hover:border-reap3r-border-light transition-all">
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <div className="w-8 h-8 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center shrink-0">
                  <Key className="text-reap3r-light" style={{ width: '12px', height: '12px' }} />
                </div>
                <div className="min-w-0">
                  <p className="text-[12px] font-semibold text-white">{k.name}</p>
                  <p className="text-[10px] text-reap3r-muted font-mono">
                    {k.key_prefix}... · {k.scopes?.join(', ')}
                    {k.last_used_at && ` · Last: ${new Date(k.last_used_at).toLocaleDateString()}`}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Badge variant={k.is_active ? 'success' : 'danger'}>{k.is_active ? 'Active' : 'Revoked'}</Badge>
                {k.is_active && (
                  <button onClick={() => revoke(k.id)} className="p-1.5 text-reap3r-muted hover:text-reap3r-warning hover:bg-reap3r-warning/10 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                    <Shield style={{ width: '12px', height: '12px' }} />
                  </button>
                )}
                <button onClick={() => deleteKey(k.id)} className="p-1.5 text-reap3r-muted hover:text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                  <Trash2 style={{ width: '12px', height: '12px' }} />
                </button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Create Key Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create API Key">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Key Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="CI/CD, Monitoring..."
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Scopes</label>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {availableScopes.map(s => (
                <button key={s} onClick={() => setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])}
                  className={`px-3 py-1.5 text-[10px] font-semibold rounded-lg uppercase tracking-[0.06em] transition-all ${
                    scopes.includes(s)
                      ? 'bg-white/8 text-white border border-white/12'
                      : 'text-reap3r-muted border border-reap3r-border hover:text-reap3r-light hover:bg-reap3r-hover'
                  }`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={create} disabled={!name}>Create</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

/* ── Integrations Tab ── */
function IntegrationsTab() {
  const [integrations, setIntegrations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ type: 'teams', name: '', config: {} as any });
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; error?: string } | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    api.alerts.integrations.list().then(r => { setIntegrations(r.data); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!form.name) return;
    await api.alerts.integrations.create(form);
    setShowCreate(false); setForm({ type: 'teams', name: '', config: {} }); load();
  };

  const deleteInteg = async (id: string) => { if (!confirm('Delete this integration?')) return; await api.alerts.integrations.delete(id); load(); };

  const testInteg = async (id: string, channel: string) => {
    setTesting(id); setTestResult(null);
    try {
      const res = await api.alerts.test(channel);
      setTestResult({ id, ok: res.ok, error: res.error });
    } catch (e: any) { setTestResult({ id, ok: false, error: e.message }); }
    setTesting(null);
  };

  const typeIcon = (t: string) => {
    if (t === 'teams') return <MessageSquare className="text-purple-400" style={{ width: '14px', height: '14px' }} />;
    if (t === 'email') return <Mail className="text-blue-400" style={{ width: '14px', height: '14px' }} />;
    if (t === 'webhook') return <Webhook className="text-green-400" style={{ width: '14px', height: '14px' }} />;
    return <Bell className="text-yellow-400" style={{ width: '14px', height: '14px' }} />;
  };

  const inputCls = "w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20";

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-[11px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Integrations</h3>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Add
        </Button>
      </div>

      {loading ? (
        <div className="space-y-2">
          {[...Array(2)].map((_, i) => <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl h-16 animate-pulse" />)}
        </div>
      ) : integrations.length === 0 ? (
        <EmptyState icon={<Webhook style={{ width: '28px', height: '28px' }} />} title="No integrations" description="Add Teams, Email, or Webhook integrations." />
      ) : (
        <div className="space-y-2">
          {integrations.map(integ => (
            <Card key={integ.id} className="!py-3 group hover:border-reap3r-border-light transition-all">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center">
                    {typeIcon(integ.type)}
                  </div>
                  <div>
                    <p className="text-[12px] font-semibold text-white">{integ.name}</p>
                    <p className="text-[10px] text-reap3r-muted capitalize">{integ.type}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={integ.is_enabled ? 'success' : 'default'}>{integ.is_enabled ? 'Active' : 'Disabled'}</Badge>
                  <button onClick={() => testInteg(integ.id, integ.type)} disabled={testing === integ.id}
                    className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                    <Send style={{ width: '12px', height: '12px' }} />
                  </button>
                  <button onClick={() => deleteInteg(integ.id)}
                    className="p-1.5 text-reap3r-muted hover:text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                    <Trash2 style={{ width: '12px', height: '12px' }} />
                  </button>
                </div>
              </div>
              {testResult?.id === integ.id && testResult && (
                <div className={`mt-3 px-3 py-2 rounded-lg text-[11px] flex items-center gap-2 ${testResult.ok ? 'bg-reap3r-success/8 text-reap3r-success' : 'bg-reap3r-danger/8 text-reap3r-danger'}`}>
                  {testResult.ok ? <CheckCircle style={{ width: '12px', height: '12px' }} /> : <AlertTriangle style={{ width: '12px', height: '12px' }} />}
                  {testResult.ok ? 'Test sent successfully' : `Failed: ${testResult.error}`}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Create Integration Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Add Integration">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Type</label>
            <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value, config: {} }))}
              className={inputCls}>
              <option value="teams">Microsoft Teams</option>
              <option value="email">Email (SMTP)</option>
              <option value="webhook">Webhook</option>
              <option value="pagerduty">PagerDuty</option>
              <option value="opsgenie">Opsgenie</option>
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Name</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Integration name" className={inputCls} />
          </div>

          {form.type === 'teams' && (
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Webhook URL</label>
              <input value={form.config.webhook_url ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, webhook_url: e.target.value } }))}
                placeholder="https://outlook.office.com/webhook/..." className={inputCls} />
            </div>
          )}
          {form.type === 'email' && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">SMTP Host</label>
                  <input value={form.config.host ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, host: e.target.value } }))} placeholder="smtp.gmail.com" className={inputCls} />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Port</label>
                  <input type="number" value={form.config.port ?? '587'} onChange={e => setForm(f => ({ ...f, config: { ...f.config, port: e.target.value } }))} placeholder="587" className={inputCls} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Username</label>
                  <input value={form.config.user ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, user: e.target.value } }))} placeholder="user@example.com" className={inputCls} />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Password</label>
                  <input type="password" value={form.config.pass ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, pass: e.target.value } }))} placeholder="••••••••" className={inputCls} />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Recipient</label>
                <input value={form.config.to ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, to: e.target.value } }))} placeholder="alerts@company.com" className={inputCls} />
              </div>
              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">From</label>
                <input value={form.config.from ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, from: e.target.value } }))} placeholder="reap3r@massvision.io" className={inputCls} />
              </div>
            </>
          )}
          {form.type === 'webhook' && (
            <>
              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">URL</label>
                <input value={form.config.url ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, url: e.target.value } }))} placeholder="https://hooks.example.com/notify" className={inputCls} />
              </div>
              <div className="space-y-1.5">
                <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Signing Secret</label>
                <input value={form.config.secret ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, secret: e.target.value } }))} placeholder="optional" className={inputCls} />
              </div>
            </>
          )}
          {form.type === 'pagerduty' && (
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Routing Key</label>
              <input value={form.config.routing_key ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, routing_key: e.target.value } }))} placeholder="PagerDuty routing key" className={inputCls} />
            </div>
          )}
          {form.type === 'opsgenie' && (
            <div className="space-y-1.5">
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">API Key</label>
              <input value={form.config.api_key ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, api_key: e.target.value } }))} placeholder="Opsgenie API key" className={inputCls} />
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={create} disabled={!form.name}>Save</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

/* ── Profile Tab ── */
function ProfileTab() {
  const { user } = useAuth();

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-4 mb-6">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center text-xl font-bold text-white"
            style={{ background: 'linear-gradient(135deg, rgba(255,255,255,0.12), rgba(255,255,255,0.04))', border: '1px solid rgba(255,255,255,0.1)' }}>
            {user?.email?.charAt(0).toUpperCase() ?? '?'}
          </div>
          <div>
            <p className="text-sm font-bold text-white">{user?.name ?? user?.email}</p>
            <p className="text-[11px] text-reap3r-muted">{user?.email}</p>
            <div className="mt-1"><Badge variant="accent">{user?.role}</Badge></div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="p-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl">
            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">User ID</p>
            <p className="text-white font-mono text-[11px] mt-1">{user?.id}</p>
          </div>
          <div className="p-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl">
            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Organization</p>
            <p className="text-white font-mono text-[11px] mt-1">{user?.org_id}</p>
          </div>
        </div>
      </Card>
    </div>
  );
}
