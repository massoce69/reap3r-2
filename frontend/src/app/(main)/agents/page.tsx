'use client';
import { useEffect, useState, useCallback, FormEvent } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, StatusDot, EmptyState, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate, statusColor } from '@/lib/utils';
import { useRealtimeRefresh, WS_AGENT_EVENTS } from '@/hooks/useRealtimeData';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import {
  Monitor, Search, RefreshCw, Download, CheckSquare, Square, CheckCheck,
  ArrowRight, ChevronLeft, ChevronRight, ArrowUpDown, ArrowUp, ArrowDown,
  FileDown, Trash2,
} from 'lucide-react';

type SortCol = 'hostname' | 'os' | 'status' | 'last_seen_at' | 'created_at';
type SortDir = 'asc' | 'desc';

export default function AgentsPage() {
  const toast = useToastHelpers();
  const [agents, setAgents] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [osFilter, setOsFilter] = useState('');
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState<SortCol>('last_seen_at');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const limit = 25;

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [latestVersion, setLatestVersion] = useState<string | null>(null);
  const [binaryAvailable, setBinaryAvailable] = useState(false);
  const [updating, setUpdating] = useState(false);

  const [showUpdateModal, setShowUpdateModal] = useState(false);
  const [updateCandidates, setUpdateCandidates] = useState<any[]>([]);
  const [updateSelection, setUpdateSelection] = useState<Set<string>>(new Set());
  const [updateSearch, setUpdateSearch] = useState('');
  const [loadingUpdateCandidates, setLoadingUpdateCandidates] = useState(false);
  const [showCurrentVersion, setShowCurrentVersion] = useState(false);

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    const params: Record<string, string> = {
      page: String(page),
      limit: String(limit),
      sort_by: sortBy,
      sort_dir: sortDir,
    };
    if (search) params.search = search;
    if (statusFilter !== 'all') params.status = statusFilter;
    if (osFilter) params.os = osFilter;

    try {
      const res = await api.agents.list(params);
      setAgents(res.data);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, osFilter, sortBy, sortDir, search]);

  const fetchManifest = async () => {
    try {
      const res = await api.agents.updateManifest();
      setLatestVersion(res.version);
      setBinaryAvailable(res.available);
    } catch {
      // no-op
    }
  };

  useEffect(() => {
    void fetchAgents();
    void fetchManifest();
  }, [fetchAgents]);

  // Real-time updates
  useRealtimeRefresh(WS_AGENT_EVENTS, fetchAgents, 2000);

  const handleSearch = (e: FormEvent) => {
    e.preventDefault();
    setPage(1);
    void fetchAgents();
  };

  const toggleSort = (col: SortCol) => {
    if (sortBy === col) setSortDir((d) => d === 'asc' ? 'desc' : 'asc');
    else {
      setSortBy(col);
      setSortDir('desc');
    }
    setPage(1);
  };

  const SortIcon = ({ col }: { col: SortCol }) => {
    if (sortBy !== col) return <ArrowUpDown className="text-reap3r-muted/30" style={{ width: '10px', height: '10px' }} />;
    return sortDir === 'asc'
      ? <ArrowUp className="text-white" style={{ width: '10px', height: '10px' }} />
      : <ArrowDown className="text-white" style={{ width: '10px', height: '10px' }} />;
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selectedIds.size === agents.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(agents.map((a) => a.id)));
  };

  const isOutdatedAgent = (agent: any) => Boolean(latestVersion && agent.agent_version !== latestVersion);
  const outdatedAgents = agents.filter(isOutdatedAgent);

  const loadUpdateCandidates = async (): Promise<any[]> => {
    setLoadingUpdateCandidates(true);
    try {
      const allAgents: any[] = [];
      const pageSize = 200;
      let pageCursor = 1;
      let totalCount = Infinity;

      while (allAgents.length < totalCount) {
        const res = await api.agents.list({
          page: String(pageCursor),
          limit: String(pageSize),
          sort_by: 'hostname',
          sort_dir: 'asc',
        });

        allAgents.push(...res.data);
        totalCount = res.total;
        if (res.data.length === 0) break;
        pageCursor += 1;
      }

      setUpdateCandidates(allAgents);
      return allAgents;
    } catch (err: any) {
      toast.error('Unable to load agents', err.message);
      return [];
    } finally {
      setLoadingUpdateCandidates(false);
    }
  };

  const openUpdateModal = async (seedIds: string[] = []) => {
    if (!binaryAvailable) {
      toast.error('Update package unavailable', 'No update manifest is available yet.');
      return;
    }

    setShowUpdateModal(true);
    setUpdateSearch('');
    setShowCurrentVersion(false);

    const allAgents = await loadUpdateCandidates();
    if (allAgents.length === 0) {
      setUpdateSelection(new Set());
      return;
    }

    const seeded = seedIds.filter((id) => allAgents.some((a) => a.id === id));
    if (seeded.length > 0) {
      setUpdateSelection(new Set(seeded));
      return;
    }

    setUpdateSelection(new Set(allAgents.filter(isOutdatedAgent).map((a) => a.id)));
  };

  const handleUpdateSelected = () => {
    void openUpdateModal(Array.from(selectedIds));
  };

  const toggleUpdateCandidate = (id: string) => {
    setUpdateSelection((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const visibleUpdateCandidates = updateCandidates.filter((agent) => {
    if (!showCurrentVersion && !isOutdatedAgent(agent)) return false;
    if (!updateSearch.trim()) return true;

    const q = updateSearch.toLowerCase();
    const text = `${agent.hostname ?? ''} ${agent.last_ip ?? ''} ${agent.os ?? ''} ${agent.company_name ?? ''}`.toLowerCase();
    return text.includes(q);
  });

  const selectedVisibleCount = visibleUpdateCandidates.filter((agent) => updateSelection.has(agent.id)).length;
  const allVisibleSelected = visibleUpdateCandidates.length > 0 && selectedVisibleCount === visibleUpdateCandidates.length;
  const totalOutdatedCandidates = updateCandidates.filter(isOutdatedAgent).length;

  const toggleSelectVisibleForUpdate = () => {
    setUpdateSelection((prev) => {
      const next = new Set(prev);
      if (allVisibleSelected) {
        visibleUpdateCandidates.forEach((agent) => next.delete(agent.id));
      } else {
        visibleUpdateCandidates.forEach((agent) => next.add(agent.id));
      }
      return next;
    });
  };

  const selectOutdatedForUpdate = () => {
    setUpdateSelection(new Set(updateCandidates.filter(isOutdatedAgent).map((a) => a.id)));
  };

  const launchSelectedUpdates = async () => {
    const selectedAgents = updateCandidates.filter((agent) => updateSelection.has(agent.id));
    const ids = selectedAgents.map((agent) => agent.id);

    if (ids.length === 0) {
      toast.info('No agent selected', 'Select at least one machine.');
      return;
    }

    const requiresForce = selectedAgents.some((agent) => !isOutdatedAgent(agent));
    setUpdating(true);
    try {
      const res = await api.agents.updateBulk(ids, { force: requiresForce });
      const queued = Array.isArray(res.results)
        ? res.results.filter((r: any) => r.status === 'queued').length
        : Number(res.total) || ids.length;
      const failed = Math.max(0, ids.length - queued);

      toast.success('Update queued', `${queued}/${ids.length} agent(s) -> v${res.version}`);
      if (failed > 0) toast.warning('Partial queue', `${failed} agent(s) could not be queued.`);

      setShowUpdateModal(false);
      setUpdateSelection(new Set());
      setSelectedIds(new Set());
      setTimeout(() => { void fetchAgents(); }, 2000);
    } catch (err: any) {
      toast.error('Update failed', err.message);
    } finally {
      setUpdating(false);
    }
  };

  const handleDeleteSelected = async () => {
    if (!confirm(`Delete ${selectedIds.size} agent(s)? This cannot be undone.`)) return;
    let deleted = 0;

    for (const id of selectedIds) {
      try {
        await api.agents.delete(id);
        deleted += 1;
      } catch {
        // continue
      }
    }

    toast.success('Deleted', `${deleted} agent(s) removed`);
    setSelectedIds(new Set());
    void fetchAgents();
  };

  const handleExport = () => {
    exportToCSV(agents, 'agents', [
      { key: 'hostname', label: 'Hostname' },
      { key: 'status', label: 'Status' },
      { key: 'os', label: 'OS' },
      { key: 'arch', label: 'Architecture' },
      { key: 'agent_version', label: 'Version' },
      { key: 'last_ip', label: 'IP Address' },
      { key: 'last_seen_at', label: 'Last Seen' },
      { key: 'company_name', label: 'Company' },
    ]);
    toast.info('Exported', `${agents.length} agents exported to CSV`);
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <>
      <TopBar title="Agents" actions={
        <div className="flex gap-2 items-center">
          {latestVersion && (
            <span className="text-[10px] text-reap3r-muted">Latest: <Badge variant="accent">v{latestVersion}</Badge></span>
          )}
          <div className="flex items-center gap-1.5 px-2 py-1 bg-reap3r-success/10 border border-reap3r-success/20 rounded-lg">
            <div className="w-1.5 h-1.5 rounded-full bg-reap3r-success animate-pulse" />
            <span className="text-[10px] font-semibold text-reap3r-success">LIVE</span>
          </div>
          <Button size="sm" onClick={() => { void openUpdateModal(); }} disabled={!binaryAvailable || updating}>
            {updating
              ? <RefreshCw className="animate-spin" style={{ width: '12px', height: '12px', marginRight: '4px' }} />
              : <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />}
            Update Agents
          </Button>
          <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
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
                <strong>{outdatedAgents.length}</strong> agent{outdatedAgents.length > 1 ? 's' : ''} outdated on this page
              </span>
            </div>
            <Button size="sm" onClick={() => { void openUpdateModal(); }} disabled={updating}>
              {updating
                ? <RefreshCw className="animate-spin" style={{ width: '12px', height: '12px', marginRight: '4px' }} />
                : <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />}
              Select Machines
            </Button>
          </div>
        )}

        {/* Filters */}
        <Card className="flex flex-wrap items-center gap-3 !py-3 !px-4">
          <form onSubmit={handleSearch} className="flex-1 min-w-[200px] flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-reap3r-muted" style={{ width: '13px', height: '13px' }} />
              <input
                className="w-full pl-9 pr-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[12px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 font-mono"
                placeholder="Search hostname, IP..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Button type="submit" variant="secondary" size="sm">Search</Button>
          </form>

          {/* OS filter */}
          <select
            value={osFilter}
            onChange={(e) => {
              setOsFilter(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none"
          >
            <option value="">All OS</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
            <option value="macos">macOS</option>
          </select>

          {/* Bulk actions */}
          {selectedIds.size > 0 && (
            <div className="flex gap-1">
              <Button size="sm" onClick={handleUpdateSelected} disabled={updating || !binaryAvailable}>
                <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />Update... ({selectedIds.size})
              </Button>
              <Button size="sm" variant="danger" onClick={handleDeleteSelected}>
                <Trash2 style={{ width: '12px', height: '12px', marginRight: '4px' }} />Delete ({selectedIds.size})
              </Button>
            </div>
          )}

          {/* Status filter */}
          <div className="flex gap-1">
            {['all', 'online', 'offline'].map((s) => (
              <button
                key={s}
                onClick={() => {
                  setStatusFilter(s);
                  setPage(1);
                }}
                className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.06em] rounded-lg transition-all ${
                  statusFilter === s ? 'bg-white/8 text-white border border-white/12' : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
                }`}
              >
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
                <th className="text-left px-4 py-3"><button onClick={() => toggleSort('status')} className="flex items-center gap-1 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] hover:text-white transition-colors">Status <SortIcon col="status" /></button></th>
                <th className="text-left px-4 py-3"><button onClick={() => toggleSort('hostname')} className="flex items-center gap-1 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] hover:text-white transition-colors">Hostname <SortIcon col="hostname" /></button></th>
                <th className="text-left px-4 py-3"><button onClick={() => toggleSort('os')} className="flex items-center gap-1 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] hover:text-white transition-colors">OS <SortIcon col="os" /></button></th>
                <th className="text-left px-4 py-3 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Version</th>
                <th className="text-left px-4 py-3 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Company</th>
                <th className="text-left px-4 py-3"><button onClick={() => toggleSort('last_seen_at')} className="flex items-center gap-1 text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] hover:text-white transition-colors">Last Seen <SortIcon col="last_seen_at" /></button></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i} className="border-b border-reap3r-border/40"><td colSpan={7} className="px-4 py-3"><div className="h-5 bg-reap3r-surface rounded animate-pulse" /></td></tr>
                ))
              ) : agents.length === 0 ? (
                <tr><td colSpan={7} className="py-12">
                  <EmptyState icon={<Monitor style={{ width: '32px', height: '32px' }} />} title="No agents found" description="Deploy your first agent to get started." />
                </td></tr>
              ) : (
                agents.map((agent) => {
                  const isOutdated = isOutdatedAgent(agent);
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
                        <p className="text-[10px] text-reap3r-muted/50 font-mono">{agent.last_ip || ''}</p>
                      </td>
                      <td className="px-4 py-3 text-[11px] text-reap3r-muted">{agent.os} {agent.arch}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <Badge variant={isOutdated ? 'default' : 'accent'}>{agent.agent_version || 'N/A'}</Badge>
                          {isOutdated && latestVersion && <span className="text-[10px] text-reap3r-warning font-semibold">{'-> '}v{latestVersion}</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[11px] text-reap3r-muted">{agent.company_name || '-'}</td>
                      <td className="px-4 py-3 text-[11px] text-reap3r-muted">{formatDate(agent.last_seen_at)}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="flex items-center justify-between px-4 py-3 border-t border-reap3r-border">
            <span className="text-[10px] text-reap3r-muted">
              {total} agents - Page {page} of {totalPages || 1}
            </span>
            <div className="flex gap-1 items-center">
              <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(1)}>First</Button>
              <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft style={{ width: '12px', height: '12px' }} />
              </Button>
              <span className="text-[11px] text-white font-mono px-2">{page}</span>
              <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                <ChevronRight style={{ width: '12px', height: '12px' }} />
              </Button>
              <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(totalPages)}>Last</Button>
            </div>
          </div>
        </Card>
      </div>

      <Modal
        open={showUpdateModal}
        onClose={() => { if (!updating) setShowUpdateModal(false); }}
        title="Update Agents"
        maxWidth="max-w-3xl"
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <p className="text-[11px] text-reap3r-muted">
              Select machines, click launch, and updates are queued automatically.
            </p>
            <div className="flex items-center gap-2">
              {latestVersion && <Badge variant="accent">Target v{latestVersion}</Badge>}
              <Badge variant="warning">{updateSelection.size} selected</Badge>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-reap3r-muted" style={{ width: '13px', height: '13px' }} />
              <input
                className="w-full pl-9 pr-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[12px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 font-mono"
                placeholder="Search hostname, IP, OS, company..."
                value={updateSearch}
                onChange={(e) => setUpdateSearch(e.target.value)}
              />
            </div>
            <label className="inline-flex items-center gap-2 px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white">
              <input
                type="checkbox"
                className="accent-white"
                checked={showCurrentVersion}
                onChange={(e) => setShowCurrentVersion(e.target.checked)}
              />
              Include up-to-date
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="secondary" onClick={toggleSelectVisibleForUpdate} disabled={loadingUpdateCandidates || visibleUpdateCandidates.length === 0}>
              {allVisibleSelected ? 'Unselect Visible' : 'Select Visible'}
            </Button>
            <Button size="sm" variant="secondary" onClick={selectOutdatedForUpdate} disabled={loadingUpdateCandidates || totalOutdatedCandidates === 0}>
              Select Outdated ({totalOutdatedCandidates})
            </Button>
          </div>

          <div className="max-h-[360px] overflow-y-auto border border-reap3r-border rounded-xl">
            {loadingUpdateCandidates ? (
              <div className="divide-y divide-reap3r-border/40">
                {[...Array(6)].map((_, i) => (
                  <div key={i} className="px-4 py-3">
                    <div className="h-4 bg-reap3r-surface rounded animate-pulse" />
                  </div>
                ))}
              </div>
            ) : visibleUpdateCandidates.length === 0 ? (
              <div className="px-4 py-10 text-center text-[11px] text-reap3r-muted">
                No machine matches this filter.
              </div>
            ) : (
              <div className="divide-y divide-reap3r-border/40">
                {visibleUpdateCandidates.map((agent) => {
                  const isOutdated = isOutdatedAgent(agent);
                  const isSelected = updateSelection.has(agent.id);
                  return (
                    <button
                      key={agent.id}
                      type="button"
                      onClick={() => toggleUpdateCandidate(agent.id)}
                      className={`w-full px-4 py-3 text-left transition-colors ${
                        isSelected ? 'bg-white/6' : 'hover:bg-reap3r-hover/40'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-3 min-w-0">
                          <span className="text-white">
                            {isSelected
                              ? <CheckSquare style={{ width: '14px', height: '14px' }} />
                              : <Square style={{ width: '14px', height: '14px' }} />}
                          </span>
                          <div className="min-w-0">
                            <p className="text-[12px] font-semibold text-white truncate">{agent.hostname}</p>
                            <p className="text-[10px] text-reap3r-muted font-mono truncate">
                              {agent.last_ip || 'No IP'} - {agent.os || 'unknown'} {agent.arch || ''}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <Badge variant={agent.status === 'online' ? 'success' : 'warning'}>{agent.status}</Badge>
                          <Badge variant={isOutdated ? 'default' : 'accent'}>{agent.agent_version || 'N/A'}</Badge>
                          {isOutdated && latestVersion && (
                            <span className="text-[10px] text-reap3r-warning font-semibold">{'-> '}v{latestVersion}</span>
                          )}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setShowUpdateModal(false)} disabled={updating}>
              Cancel
            </Button>
            <Button onClick={launchSelectedUpdates} disabled={updating || updateSelection.size === 0 || loadingUpdateCandidates}>
              {updating
                ? <RefreshCw className="animate-spin" style={{ width: '12px', height: '12px', marginRight: '4px' }} />
                : <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />}
              Launch Update ({updateSelection.size})
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
