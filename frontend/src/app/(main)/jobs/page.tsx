'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Skeleton } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { useRealtimeRefresh, WS_JOB_EVENTS } from '@/hooks/useRealtimeData';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import {
  ListTodo, ChevronDown, ChevronRight, RefreshCw, Filter,
  XCircle, FileDown, Search, ChevronLeft,
} from 'lucide-react';

const statusVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  switch (s) {
    case 'completed': return 'success';
    case 'failed':    return 'danger';
    case 'running':   return 'accent';
    case 'cancelled': return 'warning';
    default:          return 'default';
  }
};

export default function JobsPage() {
  const toast = useToastHelpers();
  const [jobs, setJobs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [agentSearch, setAgentSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const limit = 25;

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), limit: String(limit) };
    if (statusFilter) params.status = statusFilter;
    if (typeFilter) params.type = typeFilter;
    api.jobs.list(params)
      .then(r => { setJobs(r.data); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, statusFilter, typeFilter]);

  useEffect(() => { load(); }, [load]);
  useRealtimeRefresh(WS_JOB_EVENTS, load, 1500);

  const handleCancel = async (jobId: string) => {
    try {
      await api.jobs.cancel(jobId);
      toast.success('Job cancelled');
      load();
    } catch (err: any) { toast.error('Cancel failed', err.message); }
  };

  const handleExport = () => {
    exportToCSV(jobs, 'jobs', [
      { key: 'id', label: 'Job ID' },
      { key: 'type', label: 'Type' },
      { key: 'status', label: 'Status' },
      { key: 'agent_hostname', label: 'Agent' },
      { key: 'reason', label: 'Reason' },
      { key: 'created_at', label: 'Created' },
      { key: 'completed_at', label: 'Completed' },
    ]);
    toast.info('Exported', `${jobs.length} jobs exported to CSV`);
  };

  const statusFilters = ['', 'pending', 'running', 'completed', 'failed', 'cancelled'];
  const totalPages = Math.ceil(total / limit);

  // Filter by agent hostname client-side (server doesn't support hostname search on jobs)
  const filteredJobs = agentSearch
    ? jobs.filter(j => (j.agent_hostname || '').toLowerCase().includes(agentSearch.toLowerCase()))
    : jobs;

  return (
    <>
      <TopBar title="Jobs" actions={
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2 py-1 bg-reap3r-success/10 border border-reap3r-success/20 rounded-lg">
            <div className="w-1.5 h-1.5 rounded-full bg-reap3r-success animate-pulse" />
            <span className="text-[10px] font-semibold text-reap3r-success">LIVE</span>
          </div>
          <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
          <button onClick={load} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all" title="Refresh">
            <RefreshCw style={{ width: '13px', height: '13px' }} />
          </button>
        </div>
      } />

      <div className="p-6 space-y-4 animate-fade-in">
        {/* Filters */}
        <Card className="!py-3 !px-4 flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1">
            <Filter className="text-reap3r-muted shrink-0" style={{ width: '12px', height: '12px' }} />
            {statusFilters.map(s => (
              <button key={s || 'all'} onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-3 py-1.5 text-[10px] font-semibold rounded-lg uppercase tracking-[0.06em] transition-all ${
                  statusFilter === s ? 'bg-white/8 text-white border border-white/12' : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'}`}>
                {s || 'All'}
              </button>
            ))}
          </div>
          <input placeholder="Filter by type..." value={typeFilter}
            onChange={e => { setTypeFilter(e.target.value); setPage(1); }}
            className="px-3 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 w-40" />
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-reap3r-muted" style={{ width: '11px', height: '11px' }} />
            <input placeholder="Agent..." value={agentSearch}
              onChange={e => setAgentSearch(e.target.value)}
              className="pl-7 pr-3 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 w-32" />
          </div>
          <span className="text-[10px] text-reap3r-muted ml-auto font-mono">{total} jobs</span>
        </Card>

        {/* Jobs table */}
        <Card className="!p-0 overflow-hidden">
          {loading ? (
            <div className="p-4 space-y-3">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
          ) : filteredJobs.length === 0 ? (
            <EmptyState icon={<ListTodo style={{ width: '28px', height: '28px' }} />} title="No jobs found" description="Jobs dispatched to agents will appear here." />
          ) : (
            <div className="divide-y divide-reap3r-border/40">
              {filteredJobs.map(job => (
                <div key={job.id}>
                  <button
                    className="w-full flex items-center gap-4 px-5 py-3.5 hover:bg-reap3r-hover/40 transition-colors text-left group"
                    onClick={() => setExpandedId(expandedId === job.id ? null : job.id)}
                  >
                    <div className="shrink-0 text-reap3r-muted group-hover:text-reap3r-light transition-colors">
                      {expandedId === job.id ? <ChevronDown style={{ width: '13px', height: '13px' }} /> : <ChevronRight style={{ width: '13px', height: '13px' }} />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[12px] font-semibold text-white font-mono">{job.type}</span>
                        <Badge variant={statusVariant(job.status)}>{job.status}</Badge>
                      </div>
                      <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">
                        {job.agent_hostname ?? job.agent_id?.slice(0, 8)} · {formatDate(job.created_at)}
                        {job.reason && ` · ${job.reason}`}
                      </p>
                    </div>
                    {/* Cancel button for in-progress jobs */}
                    {['pending', 'queued', 'dispatched', 'running'].includes(job.status) && (
                      <button
                        onClick={(e) => { e.stopPropagation(); handleCancel(job.id); }}
                        className="px-2 py-1 text-[10px] text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all flex items-center gap-1"
                        title="Cancel job"
                      >
                        <XCircle style={{ width: '12px', height: '12px' }} /> Cancel
                      </button>
                    )}
                  </button>

                  {expandedId === job.id && (
                    <div className="px-5 pb-4 bg-reap3r-surface/30 border-t border-reap3r-border/40 space-y-3 animate-fade-in">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
                        <div><p className="text-[9px] text-reap3r-muted uppercase tracking-wider">Job ID</p><p className="text-[11px] text-white font-mono truncate">{job.id}</p></div>
                        <div><p className="text-[9px] text-reap3r-muted uppercase tracking-wider">Created By</p><p className="text-[11px] text-white">{job.created_by_name || 'System'}</p></div>
                        <div><p className="text-[9px] text-reap3r-muted uppercase tracking-wider">Created</p><p className="text-[11px] text-white font-mono">{formatDate(job.created_at)}</p></div>
                        <div><p className="text-[9px] text-reap3r-muted uppercase tracking-wider">Completed</p><p className="text-[11px] text-white font-mono">{job.completed_at ? formatDate(job.completed_at) : '—'}</p></div>
                      </div>
                      {job.payload && (
                        <div>
                          <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1.5">Payload</p>
                          <pre className="code-block text-[11px]">{JSON.stringify(job.payload, null, 2)}</pre>
                        </div>
                      )}
                      {job.result != null && (
                        <div>
                          <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1.5">Result</p>
                          <pre className="code-block text-[11px]">{typeof job.result === 'string' ? job.result : JSON.stringify(job.result, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          <div className="flex items-center justify-between px-5 py-3 border-t border-reap3r-border/60">
            <span className="text-[10px] text-reap3r-muted font-mono">{total} total · Page {page} of {totalPages || 1}</span>
            <div className="flex gap-1 items-center">
              <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(1)}>First</Button>
              <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>
                <ChevronLeft style={{ width: '12px', height: '12px' }} />
              </Button>
              <span className="text-[11px] text-white font-mono px-2">{page}</span>
              <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                <ChevronRight style={{ width: '12px', height: '12px' }} />
              </Button>
              <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(totalPages)}>Last</Button>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}
