'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { Building2, Plus, X, Pencil } from 'lucide-react';

export default function CompaniesPage() {
  const [companies, setCompanies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', domain: '', notes: '' });
  const [editId, setEditId] = useState<string | null>(null);

  const fetch = () => {
    setLoading(true);
    api.companies.list().then(r => { setCompanies(r.data); setLoading(false); }).catch(() => setLoading(false));
  };

  useEffect(() => { fetch(); }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (editId) {
      await api.companies.update(editId, form);
    } else {
      await api.companies.create(form);
    }
    setShowCreate(false); setEditId(null); setForm({ name: '', domain: '', notes: '' }); fetch();
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this company?')) return;
    await api.companies.delete(id);
    fetch();
  };

  const startEdit = (c: any) => {
    setEditId(c.id);
    setForm({ name: c.name, domain: c.domain || '', notes: c.notes || '' });
    setShowCreate(true);
  };

  return (
    <>
      <TopBar title="Companies" actions={<Button size="sm" onClick={() => { setShowCreate(true); setEditId(null); setForm({ name: '', domain: '', notes: '' }); }}><Plus className="w-4 h-4 mr-1" />Add Company</Button>} />
      <div className="p-6 space-y-4">
        {showCreate && (
          <Card>
            <form onSubmit={handleSubmit} className="space-y-3">
              <h3 className="text-sm font-semibold text-reap3r-text">{editId ? 'Edit Company' : 'New Company'}</h3>
              <input className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Company name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              <input className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Domain (optional)" value={form.domain} onChange={e => setForm({ ...form, domain: e.target.value })} />
              <textarea className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" placeholder="Notes" value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} rows={2} />
              <div className="flex gap-2">
                <Button type="submit" size="sm">{editId ? 'Update' : 'Create'}</Button>
                <Button type="button" variant="secondary" size="sm" onClick={() => setShowCreate(false)}>Cancel</Button>
              </div>
            </form>
          </Card>
        )}

        {loading ? (
          <div className="text-reap3r-muted text-sm">Loading...</div>
        ) : companies.length === 0 ? (
          <EmptyState icon={<Building2 className="w-8 h-8" />} title="No companies" description="Create your first company to organize agents." />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {companies.map(c => (
              <Card key={c.id} className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-reap3r-text">{c.name}</h3>
                  <div className="flex gap-1">
                    <button onClick={() => startEdit(c)} className="p-1 text-reap3r-muted hover:text-reap3r-accent"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => handleDelete(c.id)} className="p-1 text-reap3r-muted hover:text-reap3r-danger"><X className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
                {c.domain && <p className="text-xs text-reap3r-muted">{c.domain}</p>}
                <div className="flex gap-3 text-xs text-reap3r-muted mt-1">
                  <span>{c.agent_count ?? 0} agents</span>
                  <span>{c.online_count ?? 0} online</span>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
