'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, EmptyState, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import { FolderOpen, Plus, Pencil, Trash2, Monitor } from 'lucide-react';

export default function FoldersPage() {
  const [folders, setFolders] = useState<any[]>([]);
  const [companies, setCompanies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ name: '', company_id: '', color: '#6b6b6b', description: '' });
  const [editId, setEditId] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    Promise.all([api.folders.list(), api.companies.list()])
      .then(([f, c]) => { setFolders(f.data); setCompanies(c.data); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload = { ...form, company_id: form.company_id || undefined };
    if (editId) await api.folders.update(editId, payload);
    else await api.folders.create(payload);
    setShowModal(false); setEditId(null);
    setForm({ name: '', company_id: '', color: '#6b6b6b', description: '' });
    load();
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this folder?')) return;
    await api.folders.delete(id); load();
  };

  const startEdit = (f: any) => {
    setEditId(f.id);
    setForm({ name: f.name, company_id: f.company_id || '', color: f.color || '#6b6b6b', description: f.description || '' });
    setShowModal(true);
  };

  return (
    <>
      <TopBar
        title="Folders"
        actions={
          <Button size="sm" onClick={() => { setEditId(null); setForm({ name: '', company_id: '', color: '#6b6b6b', description: '' }); setShowModal(true); }}>
            <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />New Folder
          </Button>
        }
      />
      <div className="p-6 animate-fade-in">
        {loading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl p-6 h-32 animate-pulse" />
            ))}
          </div>
        ) : folders.length === 0 ? (
          <EmptyState
            icon={<FolderOpen style={{ width: '28px', height: '28px' }} />}
            title="No folders yet"
            description="Create folders to group agents by project, environment, or team."
          />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {folders.map(f => (
              <Card key={f.id} className="group hover:border-reap3r-border-light transition-all duration-200">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center border border-white/8"
                      style={{ backgroundColor: (f.color || '#6b6b6b') + '18' }}
                    >
                      <FolderOpen style={{ width: '18px', height: '18px', color: f.color || '#9a9a9a' }} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: f.color || '#6b6b6b' }} />
                        <h3 className="text-sm font-bold text-white">{f.name}</h3>
                      </div>
                      {f.company_name && <p className="text-[10px] text-reap3r-muted mt-0.5">{f.company_name}</p>}
                    </div>
                  </div>
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => startEdit(f)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                      <Pencil style={{ width: '12px', height: '12px' }} />
                    </button>
                    <button onClick={() => handleDelete(f.id)} className="p-1.5 text-reap3r-muted hover:text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all">
                      <Trash2 style={{ width: '12px', height: '12px' }} />
                    </button>
                  </div>
                </div>
                {f.description && <p className="text-[11px] text-reap3r-muted mb-3 leading-relaxed">{f.description}</p>}
                <div className="flex items-center gap-1.5 pt-3 border-t border-reap3r-border/60">
                  <Monitor className="text-reap3r-muted" style={{ width: '11px', height: '11px' }} />
                  <span className="text-[11px] font-bold font-mono text-white/70">{f.agent_count ?? 0}</span>
                  <span className="text-[10px] text-reap3r-muted">agents</span>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      <Modal open={showModal} onClose={() => setShowModal(false)} title={editId ? 'Edit Folder' : 'New Folder'}>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Folder Name</label>
            <input
              required
              placeholder="Production Servers"
              value={form.name}
              onChange={e => setForm({ ...form, name: e.target.value })}
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white
                placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20"
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Company</label>
            <select
              value={form.company_id}
              onChange={e => setForm({ ...form, company_id: e.target.value })}
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white
                focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20"
            >
              <option value="">No company</option>
              {companies.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-3">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Color</label>
            <input
              type="color"
              value={form.color}
              onChange={e => setForm({ ...form, color: e.target.value })}
              className="w-8 h-8 rounded-lg cursor-pointer"
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Description</label>
            <textarea
              rows={2}
              placeholder="Optional description..."
              value={form.description}
              onChange={e => setForm({ ...form, description: e.target.value })}
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
