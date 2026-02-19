'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, StatusDot, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate, statusColor } from '@/lib/utils';
import {
  Monitor, Search, RefreshCw, Download, CheckSquare, Square, CheckCheck,
  ArrowRight, ChevronLeft, ChevronRight
} from 'lucide-react';

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [latestVersion, setLatestVersion] = useState<string | null>(null);
  const [binaryAvailable, setBinaryAvailable] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updateResult, setUpdateResult] = useState<any>(null);

  const fetchAgents = () => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), limit: '25' };
    if (search) params.search = search;
    if (statusFilter !== 'all') params.status = statusFilter;
    api.agents.list(params).then((res) => {
      setAgents(res.data); setTotal(res.total); setLoading(false);
    }).catch(() => setLoading(false));
  };

  const fetchManifest = () => {
    api.agents.updateManifest().then((res) => {
      setLatestVersion(res.version); setBinaryAvailable(res.available);
    }).catch(() => {});
  };

  useEffect(() => { fetchAgents(); fetchManifest(); }, [page, statusFilter]);

  const handleSearch = (e: React.FormEvent) => { e.preventDefault(); setPage(1); fetchAgents(); };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  };
  const selectAll = () => {
    if (selectedIds.size === agents.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(agents.map(a => a.id)));
  };

  const outdatedAgents = agents.filter(a => latestVersion && a.agent_version !== latestVersion);

  const handleUpdateSelected = async (force = false) => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setUpdating(true); setUpdateResult(null);
    try {
      const res = await api.agents.updateBulk(ids, force);
      setUpdateResult(res); setSelectedIds(new Set());
      setTimeout(fetchAgents, 2000);
    } catch (err: any) { setUpdateResult({ error: err.message || 'Update failed' }); }
    finally { setUpdating(false); }
  };

  const handleUpdateAll = async () => {
    const ids = outdatedAgents.map(a => a.id);
    if (ids.length === 0) return;
    setUpdating(true); setUpdateResult(null);
    try {
      const res = await api.agents.updateBulk(ids, false);
      setUpdateResult(res); setTimeout(fetchAgents, 2000);
    } catch (err: any) { setUpdateResult({ error: err.message || 'Update failed' }); }
    finally { setUpdating(false); }
  };

  return (
    <>
      <TopBar title="Agents" actions={
        <div className="flex gap-2 items-center">
          {latestVersion && (
            <span className="text-[10px] text-reap3r-muted">
              Latest: <Badge variant="accent">v{latestVersion}</Badge>
            </span>
          )}
          <Link href="/deployment"><Button size="sm">Deploy Agent</Button></Link>
        </div>
      } />
      <div className="p-6 space-y-4 animate-fade-in">

        {/* Update banner */}
        {binaryAvailable && outdatedAgents.length > 0 && (
          <div className="flex items-center justify-between px-5 py-3 bg-reap3r-warning/6 border border-reap3r-warning/20 rounded-xl">
            <div className="flex items-center gap-3">
              <Download className="text-reap3r-warning" style={{ width: '16px', height: '16px' }} />
              <span className="text-[12px] text-white">
                <strong>{outdatedAgents.length}</strong> agent{outdatedAgents.length > 1 ? 's' : ''} outdated — update to <Badge variant="accent">v{latestVersion}</Badge>
              </span>
            </div>
            <Button size="sm" onClick={handleUpdateAll} disabled={updating}>
              {updating ? <RefreshCw className="animate-spin" style={{ width: '12px', height: '12px', marginRight: '4px' }} /> : <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />}
              Update All
            </Button>
          </div>
        )}

        {/* Update result */}
        {updateResult && (
          <div className={`px-5 py-3 rounded-xl text-[12px] ${updateResult.error ? 'bg-reap3r-danger/6 border border-reap3r-danger/20 text-reap3r-danger' : 'bg-reap3r-success/6 border border-reap3r-success/20 text-reap3r-success'}`}>
            {updateResult.error ? (
              <p>{updateResult.error}</p>
            ) : (
              <>
                <p>Update queued for <strong>{updateResult.total}</strong> agent{updateResult.total > 1 ? 's' : ''} → v{updateResult.version}</p>
                {updateResult.results?.map((r: any) => (
                  <div key={r.agent_id} className="flex items-center gap-2 text-[11px] text-reap3r-muted mt-1">
                    <span>{r.hostname}</span>
                    <Badge variant={r.status === 'queued' ? 'accent' : 'default'}>{r.status}</Badge>
                    {r.error && <span className="text-reap3r-danger">{r.error}</span>}
                  </div>
                ))}
              </>
            )}
          </div>
        )}

        {/* Filters */}
        <Card className="flex items-center gap-3 !py-3 !px-4">
          <form onSubmit={handleSearch} className="flex-1 flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-reap3r-muted" style={{ width: '13px', height: '13px' }} />
              <input
                className="w-full pl-9 pr-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[12px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20 font-mono"
                placeholder="Search hostname, IP..."
                value={search} onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Button type="submit" variant="secondary" size="sm">Search</Button>
          </form>
          {selectedIds.size > 0 && (
            <Button size="sm" onClick={() => handleUpdateSelected(false)} disabled={updating || !binaryAvailable}>
              {updating ? <RefreshCw className="animate-spin" style={{ width: '12px', height: '12px', marginRight: '4px' }} /> : <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />}
              Update ({selectedIds.size})
            </Button>
          )}
          <div className="flex gap-1">
            {['all', 'online', 'offline', 'degraded', 'pending'].map((s) => (
              <button key={s} onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.06em] rounded-lg transition-all ${
                  statusFilter === s
                    ? 'bg-white/8 text-white border border-white/12'
                    : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
                }`}>
                {s}
              </button>
            ))}
          </div>
        </Card>

        {/* Table */}
        <Card className="!p-0 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-reap3r-border bg-reap3r-surface/40">
                <th className="text-left px-3 py-3 w-10">
                  <button onClick={selectAll} className="text-reap3r-muted hover:text-white transition-colors">
                    {selectedIds.size === agents.length && agents.length > 0
                      ? <CheckCheck className="text-white" style={{ width: '14px', height: '14px' }} />
                      : <Square style={{ width: '14px', height: '14px' }} />}
                  </button>
                </th>
                {['Status', 'Hostname', 'OS', 'Version', 'Last Seen', 'Tags'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i} className="border-b border-reap3r-border/40">
                    <td colSpan={7} className="px-4 py-3"><div className="h-5 bg-reap3r-surface rounded animate-pulse" /></td>
                  </tr>
                ))
              ) : agents.length === 0 ? (
                <tr><td colSpan={7} className="py-12">
                  <EmptyState icon={<Monitor style={{ width: '32px', height: '32px' }} />} title="No agents found" description="Deploy your first agent to get started." />
                </td></tr>
              ) : (
                agents.map((agent) => {
                  const isOutdated = latestVersion && agent.agent_version !== latestVersion;
                  return (
                    <tr key={agent.id} className="border-b border-reap3r-border/40 hover:bg-reap3r-hover/50 transition-colors group">
                      <td className="px-3 py-3">
                        <button onClick={() => toggleSelect(agent.id)} className="text-reap3r-muted hover:text-white transition-colors">
                          {selectedIds.has(agent.id)
                            ? <CheckSquare className="text-white" style={{ width: '14px', height: '14px' }} />
                            : <Square style={{ width: '14px', height: '14px' }} />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <Link href={`/agents/${agent.id}`} className="flex items-center gap-2">
                          <StatusDot status={agent.status} />
                          <span className={`text-[11px] font-semibold capitalize ${statusColor(agent.status)}`}>{agent.status}</span>
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <Link href={`/agents/${agent.id}`} className="text-[12px] font-semibold text-white hover:text-reap3r-light transition-colors flex items-center gap-1">
                          {agent.hostname}
                          <ArrowRight className="text-reap3r-muted opacity-0 group-hover:opacity-100 transition-opacity" style={{ width: '10px', height: '10px' }} />
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-[11px] text-reap3r-muted">{agent.os} {agent.arch}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <Badge variant={isOutdated ? 'default' : 'accent'}>{agent.agent_version}</Badge>
                          {isOutdated && <span className="text-[10px] text-reap3r-warning font-semibold">→ v{latestVersion}</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[11px] text-reap3r-muted">{formatDate(agent.last_seen_at)}</td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1 flex-wrap">
                          {agent.tags?.map((tag: string) => <Badge key={tag} variant="accent">{tag}</Badge>)}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>

          {/* Pagination */}
          {total > 25 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-reap3r-border">
              <span className="text-[10px] text-reap3r-muted">{total} agents total</span>
              <div className="flex gap-1">
                <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft style={{ width: '12px', height: '12px', marginRight: '4px' }} /> Prev
                </Button>
                <Button variant="ghost" size="sm" disabled={agents.length < 25} onClick={() => setPage(p => p + 1)}>
                  Next <ChevronRight style={{ width: '12px', height: '12px', marginLeft: '4px' }} />
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
