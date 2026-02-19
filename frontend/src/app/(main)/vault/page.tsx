'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import {
  Lock, Plus, Eye, EyeOff, Trash2, Copy, Clock, History,
  RotateCw, X, Share2, ChevronRight, Users as UsersIcon,
  Search, FileDown, RefreshCw,
} from 'lucide-react';

const SECRET_TYPES = ['password', 'api_key', 'token', 'ssh_key', 'certificate', 'note', 'other'] as const;

export default function VaultPage() {
  const toast = useToastHelpers();
  const [secrets, setSecrets] = useState<any[]>([]);
  const [expiring, setExpiring] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<'all' | 'expiring'>('all');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', type: 'password', value: '', tags: '', notes: '', expires_at: '' });
  const [selected, setSelected] = useState<any | null>(null);
  const [revealedValue, setRevealedValue] = useState('');
  const [versions, setVersions] = useState<any[]>([]);
  const [permissions, setPermissions] = useState<any[]>([]);
  const [showShareModal, setShowShareModal] = useState(false);
  const [sharePrincipalType, setSharePrincipalType] = useState('user');
  const [sharePrincipalId, setSharePrincipalId] = useState('');
  const [shareRights, setShareRights] = useState<string[]>(['read']);
  const [search, setSearch] = useState('');

  const load = () => {
    setLoading(true);
    api.vault.list().then(r => { setSecrets(r.data); }).catch(() => {}).finally(() => setLoading(false));
    api.vault.expiring(30).then(r => setExpiring(r.data)).catch(() => {});
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const tags = form.tags ? form.tags.split(',').map(t => t.trim()) : [];
      await api.vault.create({
        name: form.name, type: form.type, value: form.value,
        tags, notes: form.notes || null, expires_at: form.expires_at || null, metadata: {},
      });
      toast.success('Secret created');
      setShowCreate(false);
      setForm({ name: '', type: 'password', value: '', tags: '', notes: '', expires_at: '' });
      load();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const selectSecret = async (secret: any) => {
    setSelected(secret); setRevealedValue('');
    api.vault.versions(secret.id).then(r => setVersions(r.data)).catch(() => setVersions([]));
    api.vault.permissions(secret.id).then(r => setPermissions(r.data)).catch(() => setPermissions([]));
  };

  const handleReveal = async () => {
    if (!selected) return;
    const mfaCode = window.prompt('Enter your 6-digit MFA code to reveal this secret');
    if (!mfaCode) return;
    try {
      const res = await api.vault.reveal(selected.id, mfaCode.trim());
      setRevealedValue(res.value);
    } catch (err: any) {
      toast.error('Reveal failed', err.message);
    }
  };

  const handleDelete = async () => {
    if (!selected || !confirm('Delete this secret permanently?')) return;
    try { await api.vault.delete(selected.id); toast.success('Secret deleted'); setSelected(null); load(); }
    catch (err: any) { toast.error('Delete failed', err.message); }
  };

  const handleRotate = async () => {
    if (!selected) return;
    try { await api.vault.rotate(selected.id); toast.success('Secret rotated'); load(); }
    catch (err: any) { toast.error('Rotate failed', err.message); }
  };

  const handleShare = async () => {
    if (!selected || !sharePrincipalId) return;
    try {
      await api.vault.share(selected.id, { principal_type: sharePrincipalType, principal_id: sharePrincipalId, rights: shareRights });
      toast.success('Secret shared');
      setShowShareModal(false); setSharePrincipalId('');
      api.vault.permissions(selected.id).then(r => setPermissions(r.data)).catch(() => {});
    } catch (err: any) { toast.error('Share failed', err.message); }
  };

  const handleRevokePermission = async (permId: string) => {
    if (!selected) return;
    try {
      await api.vault.revokePermission(selected.id, permId);
      toast.success('Permission revoked');
      api.vault.permissions(selected.id).then(r => setPermissions(r.data)).catch(() => {});
    } catch (err: any) { toast.error('Revoke failed', err.message); }
  };

  const copyToClipboard = (val: string) => { navigator.clipboard.writeText(val); toast.info('Copied to clipboard'); };

  const handleExport = () => {
    exportToCSV(displayList, 'vault-secrets', [
      { key: 'name', label: 'Name' }, { key: 'type', label: 'Type' },
      { key: 'created_at', label: 'Created' }, { key: 'expires_at', label: 'Expires' },
    ]);
    toast.info('Exported', `${displayList.length} secrets exported`);
  };

  const baseList = view === 'expiring' ? expiring : secrets;
  const displayList = search
    ? baseList.filter(s => s.name?.toLowerCase().includes(search.toLowerCase()) || s.type?.toLowerCase().includes(search.toLowerCase()))
    : baseList;

  return (
    <>
      <TopBar
        title="Vault"
        actions={
          <div className="flex items-center gap-2">
            <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
            <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
              <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />
              Add Secret
            </Button>
            <button onClick={load} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"><RefreshCw style={{ width: '13px', height: '13px' }} /></button>
          </div>
        }
      />

      <div className="flex h-[calc(100vh-3rem)]">
        {/* Left sidebar */}
        <div className="w-56 bg-reap3r-surface border-r border-reap3r-border p-3 flex flex-col gap-1 shrink-0">
          <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] px-2 py-1">Filter</p>
          {[
            { key: 'all', label: 'All Secrets', count: secrets.length, icon: Lock },
            { key: 'expiring', label: 'Expiring Soon', count: expiring.length, icon: Clock },
          ].map(({ key, label, count, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setView(key as any)}
              className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-all duration-150 ${
                view === key
                  ? 'bg-white/8 text-white border border-white/10'
                  : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
              }`}
            >
              <Icon style={{ width: '12px', height: '12px', flexShrink: 0 }} />
              <span className="flex-1 text-left font-medium">{label}</span>
              <span className="font-mono text-[10px]">{count}</span>
            </button>
          ))}
          <div className="mt-3 relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-reap3r-muted" style={{ width: '11px', height: '11px' }} />
            <input placeholder="Search..." value={search} onChange={e => setSearch(e.target.value)}
              className="w-full pl-7 pr-2 py-1.5 bg-reap3r-card border border-reap3r-border rounded-lg text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
        </div>

        {/* Main */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {showCreate && (
            <Card>
              <h3 className="text-xs font-bold text-white uppercase tracking-[0.1em] mb-4">New Secret</h3>
              <form onSubmit={handleCreate} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Name</label>
                    <input required placeholder="My API Key" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                      className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Type</label>
                    <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}
                      className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white focus:outline-none focus:ring-1 focus:ring-white/20">
                      {SECRET_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
                    </select>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Secret Value</label>
                  <textarea required rows={3} placeholder="Secret value..." value={form.value} onChange={e => setForm({ ...form, value: e.target.value })}
                    className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white font-mono placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 resize-none" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Tags</label>
                    <input placeholder="tag1, tag2" value={form.tags} onChange={e => setForm({ ...form, tags: e.target.value })}
                      className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Expires</label>
                    <input type="date" value={form.expires_at} onChange={e => setForm({ ...form, expires_at: e.target.value })}
                      className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button type="submit" size="sm">Encrypt & Save</Button>
                  <Button type="button" variant="secondary" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
                </div>
              </form>
            </Card>
          )}

          {loading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />
              ))}
            </div>
          ) : displayList.length === 0 ? (
            <EmptyState
              icon={<Lock style={{ width: '28px', height: '28px' }} />}
              title={view === 'expiring' ? 'No expiring secrets' : 'Vault is empty'}
              description={view === 'expiring' ? 'No secrets expiring within 30 days.' : 'Add secrets to securely store credentials.'}
            />
          ) : (
            <div className="space-y-2">
              {displayList.map(s => (
                <button
                  key={s.id}
                  onClick={() => selectSecret(s)}
                  className={`w-full text-left group relative bg-reap3r-card border rounded-xl px-5 py-3.5 hover:border-reap3r-border-light transition-all duration-150 ${
                    selected?.id === s.id ? 'border-white/20 bg-white/3' : 'border-reap3r-border'
                  }`}
                >
                  <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/5 to-transparent rounded-t-xl" />
                  <div className="flex items-center gap-3">
                    <Lock className="text-reap3r-muted shrink-0" style={{ width: '14px', height: '14px' }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[12px] font-semibold text-white truncate">{s.name}</p>
                      <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">
                        {s.type} · {new Date(s.created_at).toLocaleDateString()}
                        {s.expires_at ? ` · Expires ${new Date(s.expires_at).toLocaleDateString()}` : ''}
                      </p>
                    </div>
                    {s.tags?.length > 0 && (
                      <div className="flex gap-1 shrink-0">
                        {s.tags.slice(0, 2).map((tag: string, i: number) => (
                          <Badge key={i} variant="default">{tag}</Badge>
                        ))}
                      </div>
                    )}
                    <ChevronRight className="text-reap3r-muted/40 shrink-0" style={{ width: '13px', height: '13px' }} />
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Detail drawer */}
        {selected && (
          <div className="w-96 bg-reap3r-surface border-l border-reap3r-border p-6 space-y-4 overflow-y-auto shrink-0 animate-slide-up">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">{selected.name}</h3>
                <Badge variant="default">{selected.type}</Badge>
              </div>
              <button onClick={() => setSelected(null)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                <X style={{ width: '14px', height: '14px' }} />
              </button>
            </div>

            {/* Reveal */}
            <Card className="!p-4">
              <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-2">Secret Value</p>
              {revealedValue ? (
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-[11px] bg-reap3r-bg border border-reap3r-border px-2 py-1.5 rounded-lg text-white font-mono break-all">{revealedValue}</code>
                  <button onClick={() => copyToClipboard(revealedValue)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                    <Copy style={{ width: '12px', height: '12px' }} />
                  </button>
                  <button onClick={() => setRevealedValue('')} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                    <EyeOff style={{ width: '12px', height: '12px' }} />
                  </button>
                </div>
              ) : (
                <Button size="sm" onClick={handleReveal}>
                  <Eye style={{ width: '12px', height: '12px', marginRight: '4px' }} />Reveal
                </Button>
              )}
            </Card>

            {/* Versions */}
            <Card className="!p-4">
              <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-2 flex items-center gap-1.5">
                <History style={{ width: '10px', height: '10px' }} />
                Versions ({versions.length})
              </p>
              {versions.length === 0 ? (
                <p className="text-[11px] text-reap3r-muted">No previous versions.</p>
              ) : (
                <div className="space-y-1 max-h-28 overflow-y-auto">
                  {versions.map(v => (
                    <div key={v.id} className="flex items-center justify-between text-[11px] bg-reap3r-bg border border-reap3r-border p-2 rounded-lg">
                      <span className="text-reap3r-muted font-mono">{new Date(v.created_at).toLocaleString()}</span>
                      <button onClick={async () => {
                        const mfaCode = window.prompt('Enter your 6-digit MFA code to reveal this version');
                        if (!mfaCode) return;
                        try {
                          const r = await api.vault.revealVersion(selected.id, v.id, mfaCode.trim());
                          alert(`Version: ${r.value}`);
                        } catch (err: any) {
                          toast.error('Version reveal failed', err.message);
                        }
                      }}
                        className="text-white/60 hover:text-white transition-colors">View</button>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Permissions */}
            <Card className="!p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] flex items-center gap-1.5">
                  <UsersIcon style={{ width: '10px', height: '10px' }} />
                  Shared ({permissions.length})
                </p>
                <button onClick={() => setShowShareModal(true)} className="text-[10px] text-white/60 hover:text-white transition-colors flex items-center gap-1">
                  <Share2 style={{ width: '10px', height: '10px' }} />Share
                </button>
              </div>
              {permissions.length === 0 ? (
                <p className="text-[11px] text-reap3r-muted">Not shared with anyone.</p>
              ) : (
                <div className="space-y-1">
                  {permissions.map(p => (
                    <div key={p.id} className="flex items-center justify-between text-[11px] bg-reap3r-bg border border-reap3r-border p-2 rounded-lg">
                      <span className="text-reap3r-text">{p.principal_type}: {p.principal_id}</span>
                      <button onClick={() => handleRevokePermission(p.id)} className="text-reap3r-danger hover:underline text-[10px]">Revoke</button>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Actions */}
            <div className="space-y-2">
              <Button size="sm" variant="secondary" onClick={handleRotate} className="w-full">
                <RotateCw style={{ width: '12px', height: '12px', marginRight: '4px' }} />Mark as Rotated
              </Button>
              <Button size="sm" variant="danger" onClick={handleDelete} className="w-full">
                <Trash2 style={{ width: '12px', height: '12px', marginRight: '4px' }} />Delete Secret
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Share Modal */}
      <Modal open={showShareModal} onClose={() => setShowShareModal(false)} title="Share Secret">
        <div className="space-y-3">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Principal Type</label>
            <select value={sharePrincipalType} onChange={e => setSharePrincipalType(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20">
              <option value="user">User</option>
              <option value="team">Team</option>
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">User/Team ID</label>
            <input placeholder="UUID" value={sharePrincipalId} onChange={e => setSharePrincipalId(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Rights</label>
            <div className="flex gap-2 flex-wrap">
              {['read', 'write', 'reveal', 'delete'].map(right => (
                <label key={right} className="flex items-center gap-1.5 text-xs text-reap3r-text cursor-pointer">
                  <input
                    type="checkbox"
                    checked={shareRights.includes(right)}
                    onChange={e => setShareRights(e.target.checked ? [...shareRights, right] : shareRights.filter(r => r !== right))}
                    className="rounded border-reap3r-border"
                  />
                  {right}
                </label>
              ))}
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowShareModal(false)}>Cancel</Button>
            <Button onClick={handleShare}>Share</Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
