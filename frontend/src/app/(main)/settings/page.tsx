'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, Input, EmptyState } from '@/components/ui';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import {
  Settings as SettingsIcon, Globe, Shield, Key, Bell, Webhook,
  Plus, X, Copy, Eye, EyeOff, Trash2, CheckCircle, AlertTriangle,
  Mail, MessageSquare, Send,
} from 'lucide-react';

type Tab = 'organization' | 'api-keys' | 'integrations' | 'profile';

export default function SettingsPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState<Tab>('organization');

  const tabs: { key: Tab; label: string; icon: any }[] = [
    { key: 'organization', label: 'Organization', icon: Globe },
    { key: 'api-keys', label: 'API Keys', icon: Key },
    { key: 'integrations', label: 'Integrations', icon: Webhook },
    { key: 'profile', label: 'Profile', icon: Shield },
  ];

  return (
    <>
      <TopBar title="Settings" />
      <div className="p-6 space-y-4">
        <div className="flex gap-1 bg-reap3r-surface p-1 rounded-lg border border-reap3r-border w-fit">
          {tabs.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm transition-colors ${tab === t.key ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text'}`}>
              <t.icon className="w-4 h-4" />{t.label}
            </button>
          ))}
        </div>

        {tab === 'organization' && <OrganizationTab />}
        {tab === 'api-keys' && <ApiKeysTab />}
        {tab === 'integrations' && <IntegrationsTab />}
        {tab === 'profile' && <ProfileTab />}
      </div>
    </>
  );
}

// ── Organization Tab ──
function OrganizationTab() {
  const { user } = useAuth();
  return (
    <div className="space-y-6">
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-reap3r-accent" />
          Organization Details
        </h3>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs text-reap3r-muted uppercase tracking-wider">Org ID</p>
            <p className="text-reap3r-text font-mono text-xs mt-1">{user?.org_id}</p>
          </div>
          <div>
            <p className="text-xs text-reap3r-muted uppercase tracking-wider">Your Role</p>
            <Badge variant="accent">{user?.role}</Badge>
          </div>
        </div>
      </Card>

      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-reap3r-accent" />
          Role-Based Access Control
        </h3>
        <div className="space-y-3 text-sm">
          {[
            { role: 'super_admin', desc: 'Full platform access. Manage orgs, users, agents, policies, settings.' },
            { role: 'org_admin', desc: 'Full org access. Manage users, agents, jobs, policies.' },
            { role: 'operator', desc: 'Run jobs, manage agents, remote shell, view audit logs.' },
            { role: 'soc_analyst', desc: 'EDR events, detections, incidents, response actions, alerting.' },
            { role: 'viewer', desc: 'Read-only access to agents, jobs, audit logs, dashboards.' },
          ].map((r) => (
            <div key={r.role} className="flex items-start gap-3 p-3 rounded-lg bg-reap3r-surface border border-reap3r-border">
              <Badge variant={r.role === user?.role ? 'accent' : 'default'}>{r.role}</Badge>
              <p className="text-xs text-reap3r-muted">{r.desc}</p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── API Keys Tab ──
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
      setNewKey(res.key);
      setShowCreate(false);
      setName('');
      load();
    } catch (e: any) { alert(e.message); }
  };

  const revoke = async (id: string) => {
    if (!confirm('Revoke this API key?')) return;
    await api.apiKeys.revoke(id);
    load();
  };

  const deleteKey = async (id: string) => {
    if (!confirm('Permanently delete this API key?')) return;
    await api.apiKeys.delete(id);
    load();
  };

  const copyKey = () => {
    if (newKey) navigator.clipboard.writeText(newKey);
  };

  const availableScopes = ['read', 'write', 'admin', 'agents', 'jobs', 'vault', 'edr', 'alerting'];

  return (
    <div className="space-y-4">
      {/* New key display */}
      {newKey && (
        <Card className="border-reap3r-accent/30 bg-reap3r-accent/5">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-semibold text-reap3r-accent">New API Key Created</h4>
            <button onClick={() => setNewKey(null)} className="text-reap3r-muted hover:text-reap3r-text">
              <X className="w-4 h-4" />
            </button>
          </div>
          <p className="text-xs text-reap3r-muted mb-3">Copy this key now — it won't be shown again.</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-reap3r-bg border border-reap3r-border rounded px-3 py-2 text-xs font-mono text-reap3r-text overflow-x-auto">
              {showKey ? newKey : '•'.repeat(40)}
            </code>
            <Button size="sm" variant="ghost" onClick={() => setShowKey(!showKey)}>
              {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </Button>
            <Button size="sm" onClick={copyKey}>
              <Copy className="w-3 h-3 mr-1" />Copy
            </Button>
          </div>
        </Card>
      )}

      <div className="flex justify-between items-center">
        <h3 className="text-sm font-semibold text-reap3r-text">API Keys</h3>
        <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? <><X className="w-3 h-3 mr-1" />Cancel</> : <><Plus className="w-3 h-3 mr-1" />Create Key</>}
        </Button>
      </div>

      {showCreate && (
        <Card>
          <div className="space-y-3">
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Key name (e.g. CI/CD, Monitoring)" label="Name" />
            <div>
              <label className="text-sm font-medium text-reap3r-muted">Scopes</label>
              <div className="flex flex-wrap gap-2 mt-2">
                {availableScopes.map(s => (
                  <button key={s} onClick={() => setScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])}
                    className={`px-3 py-1 text-xs rounded-full border transition-colors ${scopes.includes(s) ? 'bg-reap3r-accent/10 border-reap3r-accent/30 text-reap3r-accent' : 'border-reap3r-border text-reap3r-muted hover:text-reap3r-text'}`}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
            <Button size="sm" onClick={create} disabled={!name}>Create API Key</Button>
          </div>
        </Card>
      )}

      {loading ? (
        <div className="text-sm text-reap3r-muted">Loading...</div>
      ) : keys.length === 0 ? (
        <EmptyState icon={<Key className="w-8 h-8" />} title="No API keys" description="Create API keys for programmatic access." />
      ) : (
        <div className="space-y-2">
          {keys.map(k => (
            <Card key={k.id} className="flex items-center justify-between !py-3">
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <Key className="w-4 h-4 text-reap3r-accent shrink-0" />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-reap3r-text">{k.name}</p>
                  <p className="text-xs text-reap3r-muted">
                    <span className="font-mono">{k.key_prefix}...</span>
                    {' · '}{k.scopes?.join(', ')}
                    {k.last_used_at && ` · Last used: ${new Date(k.last_used_at).toLocaleDateString()}`}
                    {k.expires_at && ` · Expires: ${new Date(k.expires_at).toLocaleDateString()}`}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Badge variant={k.is_active ? 'success' : 'danger'}>{k.is_active ? 'Active' : 'Revoked'}</Badge>
                {k.is_active && (
                  <Button size="sm" variant="ghost" onClick={() => revoke(k.id)}>Revoke</Button>
                )}
                <Button size="sm" variant="danger" onClick={() => deleteKey(k.id)}>
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Integrations Tab ──
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
    setShowCreate(false);
    setForm({ type: 'teams', name: '', config: {} });
    load();
  };

  const deleteInteg = async (id: string) => {
    if (!confirm('Delete this integration?')) return;
    await api.alerts.integrations.delete(id);
    load();
  };

  const testInteg = async (id: string, channel: string) => {
    setTesting(id);
    setTestResult(null);
    try {
      const res = await api.alerts.test(channel);
      setTestResult({ id, ok: res.ok, error: res.error });
    } catch (e: any) {
      setTestResult({ id, ok: false, error: e.message });
    }
    setTesting(null);
  };

  const typeIcons: Record<string, any> = {
    teams: <MessageSquare className="w-4 h-4 text-purple-400" />,
    email: <Mail className="w-4 h-4 text-blue-400" />,
    webhook: <Webhook className="w-4 h-4 text-green-400" />,
    pagerduty: <Bell className="w-4 h-4 text-yellow-400" />,
    opsgenie: <Bell className="w-4 h-4 text-orange-400" />,
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-sm font-semibold text-reap3r-text">Notification Integrations</h3>
        <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? <><X className="w-3 h-3 mr-1" />Cancel</> : <><Plus className="w-3 h-3 mr-1" />Add Integration</>}
        </Button>
      </div>

      {showCreate && (
        <Card>
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium text-reap3r-muted">Type</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value, config: {} }))}
                className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text mt-1">
                <option value="teams">Microsoft Teams</option>
                <option value="email">Email (SMTP)</option>
                <option value="webhook">Webhook</option>
                <option value="pagerduty">PagerDuty</option>
                <option value="opsgenie">Opsgenie</option>
              </select>
            </div>
            <Input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Integration name" label="Name" />
            
            {form.type === 'teams' && (
              <Input value={form.config.webhook_url ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, webhook_url: e.target.value } }))}
                placeholder="https://outlook.office.com/webhook/..." label="Webhook URL" />
            )}
            {form.type === 'email' && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <Input value={form.config.host ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, host: e.target.value } }))}
                    placeholder="smtp.gmail.com" label="SMTP Host" />
                  <Input type="number" value={form.config.port ?? '587'} onChange={e => setForm(f => ({ ...f, config: { ...f.config, port: e.target.value } }))}
                    placeholder="587" label="Port" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Input value={form.config.user ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, user: e.target.value } }))}
                    placeholder="user@example.com" label="Username" />
                  <Input type="password" value={form.config.pass ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, pass: e.target.value } }))}
                    placeholder="••••••••" label="Password" />
                </div>
                <Input value={form.config.to ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, to: e.target.value } }))}
                  placeholder="alerts@company.com" label="Recipient Email" />
                <Input value={form.config.from ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, from: e.target.value } }))}
                  placeholder="reap3r@massvision.io" label="From Address" />
              </>
            )}
            {form.type === 'webhook' && (
              <>
                <Input value={form.config.url ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, url: e.target.value } }))}
                  placeholder="https://hooks.example.com/notify" label="Webhook URL" />
                <Input value={form.config.secret ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, secret: e.target.value } }))}
                  placeholder="optional signing secret" label="Signing Secret (optional)" />
              </>
            )}
            {form.type === 'pagerduty' && (
              <Input value={form.config.routing_key ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, routing_key: e.target.value } }))}
                placeholder="PagerDuty routing key" label="Routing Key" />
            )}
            {form.type === 'opsgenie' && (
              <Input value={form.config.api_key ?? ''} onChange={e => setForm(f => ({ ...f, config: { ...f.config, api_key: e.target.value } }))}
                placeholder="Opsgenie API key" label="API Key" />
            )}

            <Button size="sm" onClick={create} disabled={!form.name}>Save Integration</Button>
          </div>
        </Card>
      )}

      {loading ? (
        <div className="text-sm text-reap3r-muted">Loading...</div>
      ) : integrations.length === 0 ? (
        <EmptyState icon={<Bell className="w-8 h-8" />} title="No integrations" description="Add Teams, Email, or Webhook integrations to receive alert notifications." />
      ) : (
        <div className="space-y-2">
          {integrations.map(integ => (
            <Card key={integ.id} className="!py-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {typeIcons[integ.type] ?? <Webhook className="w-4 h-4 text-reap3r-muted" />}
                  <div>
                    <p className="text-sm font-medium text-reap3r-text">{integ.name}</p>
                    <p className="text-xs text-reap3r-muted capitalize">{integ.type}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={integ.is_enabled ? 'success' : 'default'}>{integ.is_enabled ? 'Active' : 'Disabled'}</Badge>
                  <Button size="sm" variant="ghost" loading={testing === integ.id} onClick={() => testInteg(integ.id, integ.type)}>
                    <Send className="w-3 h-3 mr-1" />Test
                  </Button>
                  <Button size="sm" variant="danger" onClick={() => deleteInteg(integ.id)}>
                    <Trash2 className="w-3 h-3" />
                  </Button>
                </div>
              </div>
              {testResult?.id === integ.id && (
                <div className={`mt-3 px-3 py-2 rounded-lg text-xs flex items-center gap-2 ${testResult.ok ? 'bg-reap3r-success/10 text-reap3r-success' : 'bg-reap3r-danger/10 text-reap3r-danger'}`}>
                  {testResult.ok ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                  {testResult.ok ? 'Test notification sent successfully' : `Test failed: ${testResult.error}`}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Profile Tab ──
function ProfileTab() {
  const { user } = useAuth();

  return (
    <div className="space-y-6">
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-4">Your Profile</h3>
        <div className="flex items-center gap-4 mb-6">
          <div className="w-16 h-16 rounded-full bg-reap3r-accent/20 flex items-center justify-center text-reap3r-accent text-xl font-bold">
            {user?.email?.charAt(0).toUpperCase() ?? '?'}
          </div>
          <div>
            <p className="text-lg font-semibold text-reap3r-text">{user?.name ?? user?.email}</p>
            <p className="text-sm text-reap3r-muted">{user?.email}</p>
            <Badge variant="accent">{user?.role}</Badge>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs text-reap3r-muted uppercase tracking-wider">User ID</p>
            <p className="text-reap3r-text font-mono text-xs mt-1">{user?.id}</p>
          </div>
          <div>
            <p className="text-xs text-reap3r-muted uppercase tracking-wider">Organization</p>
            <p className="text-reap3r-text font-mono text-xs mt-1">{user?.org_id}</p>
          </div>
        </div>
      </Card>
    </div>
  );
}
