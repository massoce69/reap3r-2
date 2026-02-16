'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { Lock, Plus, Eye, EyeOff, Trash2, Copy, Clock, Users as UsersIcon, History, RotateCw, X, Share2, ChevronRight } from 'lucide-react';

const SECRET_TYPES = ['password', 'api_key', 'token', 'ssh_key', 'certificate', 'note', 'other'] as const;

export default function VaultPage() {
  const [secrets, setSecrets] = useState<any[]>([]);
  const [expiring, setExpiring] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<'all' | 'expiring'>('all');
  
  // Create Secret
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', type: 'password', value: '', tags: '', notes: '', expires_at: '' });

  // Selected Secret & Detail Drawer
  const [selected, setSelected] = useState<any | null>(null);
  const [revealedValue, setRevealedValue] = useState('');
  const [versions, setVersions] = useState<any[]>([]);
  const [permissions, setPermissions] = useState<any[]>([]);
  const [showShareModal, setShowShareModal] = useState(false);
  const [sharePrincipalType, setSharePrincipalType] = useState('user');
  const [sharePrincipalId, setSharePrincipalId] = useState('');
  const [shareRights, setShareRights] = useState<string[]>(['read']);

  const load = () => {
    setLoading(true);
    api.vault.list().then(r => { setSecrets(r.data); setLoading(false); }).catch(() => setLoading(false));
    api.vault.expiring(30).then(r => setExpiring(r.data)).catch(() => {});
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const tags = form.tags ? form.tags.split(',').map(t => t.trim()) : [];
    const metadata = {};
    await api.vault.create({ 
      name: form.name, 
      type: form.type, 
      value: form.value, 
      tags, 
      notes: form.notes || null, 
      expires_at: form.expires_at || null, 
      metadata 
    });
    setShowCreate(false); 
    setForm({ name: '', type: 'password', value: '', tags: '', notes: '', expires_at: '' }); 
    load();
  };

  const selectSecret = async (secret: any) => {
    setSelected(secret);
    setRevealedValue('');
    // Load versions, permissions
    api.vault.versions(secret.id).then(r => setVersions(r.data)).catch(() => setVersions([]));
    api.vault.permissions(secret.id).then(r => setPermissions(r.data)).catch(() => setPermissions([]));
  };

  const handleReveal = async () => {
    if (!selected) return;
    const res = await api.vault.reveal(selected.id);
    setRevealedValue(res.value);
  };

  const handleDelete = async () => {
    if (!selected || !confirm('Delete this secret permanently?')) return;
    await api.vault.delete(selected.id); 
    setSelected(null);
    load();
  };

  const handleRotate = async () => {
    if (!selected) return;
    await api.vault.rotate(selected.id);
    alert('Secret marked as rotated. Update with new value if needed.');
    load();
  };

  const handleShare = async () => {
    if (!selected || !sharePrincipalId) return;
    await api.vault.share(selected.id, { principal_type: sharePrincipalType, principal_id: sharePrincipalId, rights: shareRights });
    setShowShareModal(false);
    setSharePrincipalId('');
    // Reload permissions
    api.vault.permissions(selected.id).then(r => setPermissions(r.data)).catch(() => {});
  };

  const handleRevokePermission = async (permId: string) => {
    if (!selected) return;
    await api.vault.revokePermission(selected.id, permId);
    api.vault.permissions(selected.id).then(r => setPermissions(r.data)).catch(() => {});
  };

  const copyToClipboard = (val: string) => {
    navigator.clipboard.writeText(val);
    alert('Copied to clipboard');
  };

  const displayList = view === 'expiring' ? expiring : secrets;

  return (
    <>
      <TopBar title="Vault" actions={<Button size="sm" onClick={() => setShowCreate(true)}><Plus className="w-4 h-4 mr-1" />Add Secret</Button>} />
      
      <div className="flex h-[calc(100vh-4rem)]">
        {/* Sidebar */}
        <div className="w-64 bg-reap3r-surface border-r border-reap3r-border p-4 space-y-2">
          <button onClick={() => setView('all')} className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${view === 'all' ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-bg'}`}>
            <Lock className="w-4 h-4 inline mr-2" />All Secrets ({secrets.length})
          </button>
          <button onClick={() => setView('expiring')} className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${view === 'expiring' ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-bg'}`}>
            <Clock className="w-4 h-4 inline mr-2" />Expiring Soon ({expiring.length})
          </button>
        </div>

        {/* Main Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {showCreate && (
            <Card>
              <form onSubmit={handleCreate} className="space-y-3">
                <h3 className="text-sm font-semibold text-reap3r-text">New Secret</h3>
                <input className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Secret name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
                <select className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}>
                  {SECRET_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
                </select>
                <textarea className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text font-mono" placeholder="Secret value" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} rows={3} required />
                <input className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Tags (comma-separated)" value={form.tags} onChange={e => setForm({ ...form, tags: e.target.value })} />
                <textarea className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Notes (optional)" value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} rows={2} />
                <input type="date" className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Expiration date (optional)" value={form.expires_at} onChange={e => setForm({ ...form, expires_at: e.target.value })} />
                <div className="flex gap-2">
                  <Button type="submit" size="sm">Encrypt & Save</Button>
                  <Button type="button" variant="secondary" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
                </div>
              </form>
            </Card>
          )}

          {loading ? (
            <div className="text-reap3r-muted text-sm">Loading...</div>
          ) : displayList.length === 0 ? (
            <EmptyState icon={<Lock className="w-8 h-8" />} title={view === 'expiring' ? 'No expiring secrets' : 'Vault is empty'} description={view === 'expiring' ? 'Secrets expiring within 30 days will appear here.' : 'Add secrets to securely store credentials.'} />
          ) : (
            <div className="space-y-2">
              {displayList.map(s => (
                <div key={s.id} onClick={() => selectSecret(s)} className="cursor-pointer">
                  <Card className="flex items-center justify-between !py-3 hover:bg-reap3r-bg transition-colors">
                    <div className="flex items-center gap-3 flex-1">
                      <Lock className="w-4 h-4 text-reap3r-accent" />
                      <div className="flex-1">
                        <p className="text-sm font-medium text-reap3r-text">{s.name}</p>
                        <p className="text-xs text-reap3r-muted">{s.type} · Created {new Date(s.created_at).toLocaleDateString()}{s.expires_at ? ` · Expires ${new Date(s.expires_at).toLocaleDateString()}` : ''}</p>
                      </div>
                      {s.tags && s.tags.length > 0 && (
                        <div className="flex gap-1">
                          {s.tags.slice(0, 2).map((tag: string, i: number) => (
                            <span key={i} className="text-xs bg-reap3r-accent/10 text-reap3r-accent px-2 py-0.5 rounded">{tag}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    <ChevronRight className="w-4 h-4 text-reap3r-muted" />
                  </Card>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Detail Drawer */}
        {selected && (
          <div className="w-96 bg-reap3r-surface border-l border-reap3r-border p-6 space-y-4 overflow-y-auto">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-reap3r-text">{selected.name}</h3>
                <p className="text-xs text-reap3r-muted">{selected.type}</p>
              </div>
              <button onClick={() => setSelected(null)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>

            {/* Reveal Secret */}
            <Card>
              <div className="space-y-2">
                <p className="text-xs text-reap3r-muted font-semibold">Secret Value</p>
                {revealedValue ? (
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-xs bg-reap3r-bg px-2 py-1 rounded text-reap3r-accent font-mono break-all">{revealedValue}</code>
                    <button onClick={() => copyToClipboard(revealedValue)} className="p-1 text-reap3r-muted hover:text-reap3r-accent"><Copy className="w-4 h-4" /></button>
                    <button onClick={() => setRevealedValue('')} className="p-1 text-reap3r-muted hover:text-reap3r-accent"><EyeOff className="w-4 h-4" /></button>
                  </div>
                ) : (
                  <Button size="sm" onClick={handleReveal}><Eye className="w-3 h-3 mr-1" />Reveal</Button>
                )}
              </div>
            </Card>

            {/* Versions History */}
            <Card>
              <div className="space-y-2">
                <p className="text-xs text-reap3r-muted font-semibold flex items-center gap-1"><History className="w-3 h-3" />Versions ({versions.length})</p>
                {versions.length === 0 ? (
                  <p className="text-xs text-reap3r-muted">No previous versions.</p>
                ) : (
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {versions.map(v => (
                      <div key={v.id} className="text-xs text-reap3r-text bg-reap3r-bg p-2 rounded flex items-center justify-between">
                        <span>{new Date(v.created_at).toLocaleString()}</span>
                        <button onClick={() => api.vault.revealVersion(selected.id, v.id).then(r => alert(`Version: ${r.value}`))} className="text-reap3r-accent hover:underline">View</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>

            {/* Sharing & Permissions */}
            <Card>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-reap3r-muted font-semibold flex items-center gap-1"><UsersIcon className="w-3 h-3" />Shared With ({permissions.length})</p>
                  <button onClick={() => setShowShareModal(true)} className="text-xs text-reap3r-accent hover:underline flex items-center gap-1"><Share2 className="w-3 h-3" />Share</button>
                </div>
                {permissions.length === 0 ? (
                  <p className="text-xs text-reap3r-muted">Not shared.</p>
                ) : (
                  <div className="space-y-1">
                    {permissions.map(p => (
                      <div key={p.id} className="text-xs text-reap3r-text bg-reap3r-bg p-2 rounded flex items-center justify-between">
                        <span>{p.principal_type}: {p.principal_id}</span>
                        <button onClick={() => handleRevokePermission(p.id)} className="text-reap3r-danger hover:underline">Revoke</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>

            {/* Actions */}
            <div className="space-y-2">
              <Button size="sm" variant="secondary" onClick={handleRotate} className="w-full"><RotateCw className="w-3 h-3 mr-1" />Mark as Rotated</Button>
              <Button size="sm" variant="danger" onClick={handleDelete} className="w-full"><Trash2 className="w-3 h-3 mr-1" />Delete Secret</Button>
            </div>
          </div>
        )}
      </div>

      {/* Share Modal */}
      {showShareModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowShareModal(false)}>
          <div className="bg-reap3r-surface border border-reap3r-border rounded-lg p-6 max-w-md w-full m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-reap3r-text">Share Secret</h3>
              <button onClick={() => setShowShareModal(false)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-3">
              <select value={sharePrincipalType} onChange={e => setSharePrincipalType(e.target.value)} className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text">
                <option value="user">User</option>
                <option value="team">Team</option>
              </select>
              <input placeholder="User/Team ID" value={sharePrincipalId} onChange={e => setSharePrincipalId(e.target.value)} className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" />
              <div className="flex gap-2 flex-wrap">
                {['read', 'write', 'reveal', 'delete'].map(right => (
                  <label key={right} className="flex items-center gap-1 text-xs text-reap3r-text">
                    <input type="checkbox" checked={shareRights.includes(right)} onChange={e => setShareRights(e.target.checked ? [...shareRights, right] : shareRights.filter(r => r !== right))} />
                    {right}
                  </label>
                ))}
              </div>
              <Button onClick={handleShare}>Share</Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
