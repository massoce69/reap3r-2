'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import { Building2, Plus, Pencil, Trash2, Monitor, Wifi, Search, FileDown, RefreshCw } from 'lucide-react';

export default function CompaniesPage() {
  const toast = useToastHelpers();
  const [companies, setCompanies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ name: '', notes: '' });
  const [editId, setEditId] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    api.companies.list().then(r => { setCompanies(r.data); }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editId) { await api.companies.update(editId, form); toast.success('Company updated'); }
      else { await api.companies.create(form); toast.success('Company created'); }
      setShowModal(false); setEditId(null); setForm({ name: '', notes: '' }); load();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this company and all associated data?')) return;
    try { await api.companies.delete(id); toast.success('Company deleted'); load(); }
    catch (err: any) { toast.error('Delete failed', err.message); }
  };

  const startEdit = (c: any) => {
    setEditId(c.id); setForm({ name: c.name, notes: c.notes || '' }); setShowModal(true);
  };

  const openCreate = () => {
    setEditId(null); setForm({ name: '', notes: '' }); setShowModal(true);
  };

  const handleExport = () => {
    exportToCSV(filtered, 'companies', [
      { key: 'name', label: 'Name' }, { key: 'notes', label: 'Notes' },
      { key: 'agent_count', label: 'Agents' }, { key: 'online_count', label: 'Online' },
    ]);
    toast.info('Exported', `${filtered.length} companies exported`);
  };

  const filtered = search
    ? companies.filter(c => c.name?.toLowerCase().includes(search.toLowerCase()) || c.notes?.toLowerCase().includes(search.toLowerCase()))
    : companies;

  return (
    <>
      <TopBar
        title="Companies"
        actions={
          <div className="flex items-center gap-2">
            <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
            <Button size="sm" onClick={openCreate}><Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />New Company</Button>
            <button onClick={load} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"><RefreshCw style={{ width: '13px', height: '13px' }} /></button>
          </div>
        }
      />

      <div className="p-6 animate-fade-in space-y-4">
        {/* Search */}
        <Card className="!py-3 !px-4 flex items-center gap-3">
          <Search className="text-reap3r-muted shrink-0" style={{ width: '12px', height: '12px' }} />
          <input placeholder="Search companies..." value={search} onChange={e => setSearch(e.target.value)}
            className="flex-1 bg-transparent border-none text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none" />
          <span className="text-[10px] text-reap3r-muted font-mono">{filtered.length} companies</span>
        </Card>
        {loading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl p-6 h-32 animate-pulse" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<Building2 style={{ width: '28px', height: '28px' }} />}
            title="No companies yet"
            description="Create your first company to organize agents by client or department."
          />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {filtered.map(c => (
              <Card key={c.id} className="group hover:border-reap3r-border-light transition-all duration-200">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/8 flex items-center justify-center">
                      <Building2 className="text-white/60" style={{ width: '18px', height: '18px' }} />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white">{c.name}</h3>
                      {c.domain && <p className="text-[10px] text-reap3r-muted font-mono">{c.domain}</p>}
                    </div>
                  </div>
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => startEdit(c)}
                      className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"
                    >
                      <Pencil style={{ width: '12px', height: '12px' }} />
                    </button>
                    <button
                      onClick={() => handleDelete(c.id)}
                      className="p-1.5 text-reap3r-muted hover:text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all"
                    >
                      <Trash2 style={{ width: '12px', height: '12px' }} />
                    </button>
                  </div>
                </div>

                {c.notes && (
                  <p className="text-[11px] text-reap3r-muted mb-4 leading-relaxed">{c.notes}</p>
                )}

                <div className="flex items-center gap-4 pt-3 border-t border-reap3r-border/60">
                  <div className="flex items-center gap-1.5">
                    <Monitor className="text-reap3r-muted" style={{ width: '11px', height: '11px' }} />
                    <span className="text-[11px] font-semibold text-reap3r-light font-mono">{c.agent_count ?? 0}</span>
                    <span className="text-[10px] text-reap3r-muted">agents</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Wifi className="text-reap3r-success" style={{ width: '11px', height: '11px' }} />
                    <span className="text-[11px] font-semibold text-reap3r-success font-mono">{c.online_count ?? 0}</span>
                    <span className="text-[10px] text-reap3r-muted">online</span>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      <Modal open={showModal} onClose={() => setShowModal(false)} title={editId ? 'Edit Company' : 'New Company'}>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Company Name</label>
            <input
              required
              placeholder="Acme Corporation"
              value={form.name}
              onChange={e => setForm({ ...form, name: e.target.value })}
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white
                placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20"
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Notes (optional)</label>
            <textarea
              rows={3}
              placeholder="Additional notes..."
              value={form.notes}
              onChange={e => setForm({ ...form, notes: e.target.value })}
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white
                placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20 resize-none"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button type="button" variant="secondary" onClick={() => setShowModal(false)}>Cancel</Button>
            <Button type="submit">{editId ? 'Update' : 'Create'}</Button>
          </div>
        </form>
      </Modal>
    </>
  );
}
