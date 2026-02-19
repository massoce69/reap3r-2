'use client';
import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Input, Badge, StatusDot, EmptyState, Skeleton } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate, statusColor } from '@/lib/utils';
import { Monitor, Search, Filter, RefreshCw, Download, CheckSquare, Square, CheckCheck } from 'lucide-react';

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);

  // Update system
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
      setAgents(res.data);
      setTotal(res.total);
      setLoading(false);
    }).catch(() => setLoading(false));
  };

  const fetchManifest = () => {
    api.agents.updateManifest().then((res) => {
      setLatestVersion(res.version);
      setBinaryAvailable(res.available);
    }).catch(() => {});
  };

  useEffect(() => { fetchAgents(); fetchManifest(); }, [page, statusFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAgents();
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selectedIds.size === agents.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(agents.map(a => a.id)));
    }
  };

  // Agents that are outdated (version != latestVersion)
  const outdatedAgents = agents.filter(a => latestVersion && a.agent_version !== latestVersion);
  const selectedOutdated = agents.filter(a => selectedIds.has(a.id) && latestVersion && a.agent_version !== latestVersion);

  const handleUpdateSelected = async (force = false) => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setUpdating(true);
    setUpdateResult(null);
    try {
      const res = await api.agents.updateBulk(ids, force);
      setUpdateResult(res);
      setSelectedIds(new Set());
      // Refresh list after a short delay
      setTimeout(fetchAgents, 2000);
    } catch (err: any) {
      setUpdateResult({ error: err.message || 'Update failed' });
    } finally {
      setUpdating(false);
    }
  };

  const handleUpdateAll = async () => {
    const ids = outdatedAgents.map(a => a.id);
    if (ids.length === 0) return;
    setUpdating(true);
    setUpdateResult(null);
    try {
      const res = await api.agents.updateBulk(ids, false);
      setUpdateResult(res);
      setTimeout(fetchAgents, 2000);
    } catch (err: any) {
      setUpdateResult({ error: err.message || 'Update failed' });
    } finally {
      setUpdating(false);
    }
  };

  return (
    <>
      <TopBar title="Agents" actions={
        <div className="flex gap-2 items-center">
          {latestVersion && (
            <span className="text-xs text-reap3r-muted">
              Dernière version: <Badge variant="accent">v{latestVersion}</Badge>
            </span>
          )}
          <Link href="/deployment">
            <Button size="sm">Deploy Agent</Button>
          </Link>
        </div>
      } />
      <div className="p-6 space-y-4">
        {/* Update banner */}
        {binaryAvailable && outdatedAgents.length > 0 && (
          <Card className="!py-3 bg-amber-500/5 border-amber-500/20">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Download className="w-5 h-5 text-amber-500" />
                <span className="text-sm text-reap3r-text">
                  <strong>{outdatedAgents.length}</strong> agent{outdatedAgents.length > 1 ? 's' : ''} nécessite{outdatedAgents.length > 1 ? 'nt' : ''} une mise à jour vers <Badge variant="accent">v{latestVersion}</Badge>
                </span>
              </div>
              <Button size="sm" onClick={handleUpdateAll} disabled={updating}>
                {updating ? <RefreshCw className="w-4 h-4 animate-spin mr-1" /> : <Download className="w-4 h-4 mr-1" />}
                Mettre à jour tous
              </Button>
            </div>
          </Card>
        )}

        {/* Update result */}
        {updateResult && (
          <Card className={`!py-3 ${updateResult.error ? 'bg-red-500/5 border-red-500/20' : 'bg-green-500/5 border-green-500/20'}`}>
            {updateResult.error ? (
              <p className="text-sm text-red-400">{updateResult.error}</p>
            ) : (
              <div className="text-sm text-green-400">
                <p>Mise à jour lancée pour <strong>{updateResult.total}</strong> agent{updateResult.total > 1 ? 's' : ''} → v{updateResult.version}</p>
                <div className="mt-1 space-y-0.5 text-xs text-reap3r-muted">
                  {updateResult.results?.map((r: any) => (
                    <div key={r.agent_id} className="flex items-center gap-2">
                      <span>{r.hostname}</span>
                      <Badge variant={r.status === 'queued' ? 'accent' : 'default'}>{r.status}</Badge>
                      {r.error && <span className="text-red-400">{r.error}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        )}

        {/* Filters */}
        <Card className="flex items-center gap-4 !py-3">
          <form onSubmit={handleSearch} className="flex-1 flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-reap3r-muted" />
              <input
                className="w-full pl-9 pr-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-reap3r-text placeholder:text-reap3r-muted/50 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50"
                placeholder="Search hostname, IP..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Button type="submit" variant="secondary" size="sm">Search</Button>
          </form>
          {selectedIds.size > 0 && (
            <Button size="sm" onClick={() => handleUpdateSelected(false)} disabled={updating || !binaryAvailable}>
              {updating ? <RefreshCw className="w-4 h-4 animate-spin mr-1" /> : <Download className="w-4 h-4 mr-1" />}
              Mettre à jour ({selectedIds.size})
            </Button>
          )}
          <div className="flex gap-1">
            {['all', 'online', 'offline', 'degraded', 'pending'].map((s) => (
              <button
                key={s}
                onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  statusFilter === s
                    ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                    : 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-hover'
                }`}
              >
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
        </Card>

        {/* Table */}
        <Card className="!p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-reap3r-border bg-reap3r-surface/50">
                <th className="text-left px-3 py-3 w-10">
                  <button onClick={selectAll} className="text-reap3r-muted hover:text-reap3r-text">
                    {selectedIds.size === agents.length && agents.length > 0 ? <CheckCheck className="w-4 h-4 text-reap3r-accent" /> : <Square className="w-4 h-4" />}
                  </button>
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Hostname</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">OS</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Version</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Last Seen</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Tags</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i} className="border-b border-reap3r-border/50">
                    <td colSpan={7} className="px-4 py-3"><Skeleton className="h-6 w-full" /></td>
                  </tr>
                ))
              ) : agents.length === 0 ? (
                <tr><td colSpan={7}><EmptyState icon={<Monitor className="w-12 h-12" />} title="No agents found" description="Deploy your first agent to get started." /></td></tr>
              ) : (
                agents.map((agent) => {
                  const isOutdated = latestVersion && agent.agent_version !== latestVersion;
                  return (
                    <tr key={agent.id} className="border-b border-reap3r-border/50 hover:bg-reap3r-hover/50 transition-colors">
                      <td className="px-3 py-3">
                        <button onClick={() => toggleSelect(agent.id)} className="text-reap3r-muted hover:text-reap3r-text">
                          {selectedIds.has(agent.id)
                            ? <CheckSquare className="w-4 h-4 text-reap3r-accent" />
                            : <Square className="w-4 h-4" />
                          }
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <Link href={`/agents/${agent.id}`} className="flex items-center gap-2">
                          <StatusDot status={agent.status} />
                          <span className={`text-xs font-medium capitalize ${statusColor(agent.status)}`}>{agent.status}</span>
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <Link href={`/agents/${agent.id}`} className="font-medium text-reap3r-text hover:text-reap3r-accent">{agent.hostname}</Link>
                      </td>
                      <td className="px-4 py-3 text-reap3r-muted">{agent.os} {agent.arch}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <Badge variant={isOutdated ? 'default' : 'accent'}>{agent.agent_version}</Badge>
                          {isOutdated && (
                            <span className="text-[10px] text-amber-500 font-medium">⬆ v{latestVersion}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-reap3r-muted text-xs">{formatDate(agent.last_seen_at)}</td>
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
              <span className="text-xs text-reap3r-muted">{total} agents total</span>
              <div className="flex gap-1">
                <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
                <Button variant="ghost" size="sm" disabled={agents.length < 25} onClick={() => setPage(p => p + 1)}>Next</Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
