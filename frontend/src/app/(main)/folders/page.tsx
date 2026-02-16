'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { FolderOpen, Plus, X, Pencil } from 'lucide-react';

export default function FoldersPage() {
  const [folders, setFolders] = useState<any[]>([]);
  const [companies, setCompanies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', company_id: '', color: '#6366f1', description: '' });
  const [editId, setEditId] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    Promise.all([api.folders.list(), api.companies.list()]).then(([f, c]) => {
      setFolders(f.data); setCompanies(c.data); setLoading(false);
    }).catch(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload = { ...form, company_id: form.company_id || undefined };
    if (editId) await api.folders.update(editId, payload);
    else await api.folders.create(payload);
    setShowCreate(false); setEditId(null); setForm({ name: '', company_id: '', color: '#6366f1', description: '' }); load();
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this folder?')) return;
    await api.folders.delete(id); load();
  };

  const startEdit = (f: any) => {
    setEditId(f.id);
    setForm({ name: f.name, company_id: f.company_id || '', color: f.color || '#6366f1', description: f.description || '' });
    setShowCreate(true);
  };

  return (
    <>
      <TopBar title="Folders" actions={<Button size="sm" onClick={() => { setShowCreate(true); setEditId(null); setForm({ name: '', company_id: '', color: '#6366f1', description: '' }); }}><Plus className="w-4 h-4 mr-1" />Add Folder</Button>} />
      <div className="p-6 space-y-4">
        {showCreate && (
          <Card>
            <form onSubmit={handleSubmit} className="space-y-3">
              <h3 className="text-sm font-semibold text-reap3r-text">{editId ? 'Edit Folder' : 'New Folder'}</h3>
              <input className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Folder name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              <select className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" value={form.company_id} onChange={e => setForm({ ...form, company_id: e.target.value })}>
                <option value="">No company</option>
                {companies.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
              <div className="flex gap-3 items-center">
                <label className="text-xs text-reap3r-muted">Color:</label>
                <input type="color" value={form.color} onChange={e => setForm({ ...form, color: e.target.value })} className="w-8 h-8 rounded cursor-pointer" />
              </div>
              <textarea className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2} />
              <div className="flex gap-2">
                <Button type="submit" size="sm">{editId ? 'Update' : 'Create'}</Button>
                <Button type="button" variant="secondary" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
              </div>
            </form>
          </Card>
        )}

        {loading ? (
          <div className="text-reap3r-muted text-sm">Loading...</div>
        ) : folders.length === 0 ? (
          <EmptyState icon={<FolderOpen className="w-8 h-8" />} title="No folders" description="Create folders to group your agents." />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {folders.map(f => (
              <Card key={f.id} className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: f.color || '#6366f1' }} />
                    <h3 className="font-semibold text-reap3r-text">{f.name}</h3>
                  </div>
                  <div className="flex gap-1">
                    <button onClick={() => startEdit(f)} className="p-1 text-reap3r-muted hover:text-reap3r-accent"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => handleDelete(f.id)} className="p-1 text-reap3r-muted hover:text-reap3r-danger"><X className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
                {f.company_name && <p className="text-xs text-reap3r-muted">Company: {f.company_name}</p>}
                <p className="text-xs text-reap3r-muted">{f.agent_count ?? 0} agents</p>
              </Card>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
