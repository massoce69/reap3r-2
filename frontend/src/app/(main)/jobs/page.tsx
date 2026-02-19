'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Skeleton } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { ListTodo, ChevronDown, ChevronRight, RefreshCw, Filter } from 'lucide-react';

const statusVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  switch (s) {
    case 'completed': return 'success';
    case 'failed':    return 'danger';
    case 'running':   return 'accent';
    default:          return 'default';
  }
};

export default function JobsPage() {
  const [jobs, setJobs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), limit: '25' };
    if (statusFilter) params.status = statusFilter;
    if (typeFilter) params.type = typeFilter;
    api.jobs.list(params)
      .then(r => { setJobs(r.data); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, statusFilter, typeFilter]);

  useEffect(() => { load(); }, [load]);

  const statusFilters = ['', 'pending', 'running', 'completed', 'failed'];

  return (
    <>
      <TopBar
        title="Jobs"
        actions={
          <button onClick={load} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all" title="Refresh">
            <RefreshCw style={{ width: '13px', height: '13px' }} />
          </button>
        }
      />

      <div className="p-6 space-y-4 animate-fade-in">
        {/* Filters */}
        <Card className="!py-3 !px-4 flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1">
            <Filter className="text-reap3r-muted shrink-0" style={{ width: '12px', height: '12px' }} />
            {statusFilters.map(s => (
              <button
                key={s || 'all'}
                onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-3 py-1.5 text-[10px] font-semibold rounded-lg uppercase tracking-[0.06em] transition-all ${
                  statusFilter === s
                    ? 'bg-white/8 text-white border border-white/12'
                    : 'text-reap3r-muted hover:text-reap3r-light hover:bg-reap3r-hover'
                }`}
              >
                {s || 'All'}
              </button>
            ))}
          </div>
          <input
            placeholder="Filter by type..."
            value={typeFilter}
            onChange={e => { setTypeFilter(e.target.value); setPage(1); }}
            className="px-3 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 w-40"
          />
          <span className="text-[10px] text-reap3r-muted ml-auto font-mono">{total} jobs</span>
        </Card>

        {/* Jobs table */}
        <Card className="!p-0 overflow-hidden">
          {loading ? (
            <div className="p-4 space-y-3">
              {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : jobs.length === 0 ? (
            <EmptyState
              icon={<ListTodo style={{ width: '28px', height: '28px' }} />}
              title="No jobs found"
              description="Jobs dispatched to agents will appear here."
            />
          ) : (
            <div className="divide-y divide-reap3r-border/40">
              {jobs.map(job => (
                <div key={job.id}>
                  <button
                    className="w-full flex items-center gap-4 px-5 py-3.5 hover:bg-reap3r-hover/40 transition-colors text-left group"
                    onClick={() => setExpandedId(expandedId === job.id ? null : job.id)}
                  >
                    <div className="shrink-0 text-reap3r-muted group-hover:text-reap3r-light transition-colors">
                      {expandedId === job.id
                        ? <ChevronDown style={{ width: '13px', height: '13px' }} />
                        : <ChevronRight style={{ width: '13px', height: '13px' }} />
                      }
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[12px] font-semibold text-white font-mono">{job.type}</span>
                        <Badge variant={statusVariant(job.status)}>{job.status}</Badge>
                      </div>
                      <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">
                        {job.agent_hostname ?? job.agent_id?.slice(0, 8)} · {formatDate(job.created_at)}
                      </p>
                    </div>
                    {job.duration_ms != null && (
                      <span className="text-[10px] text-reap3r-muted font-mono shrink-0">
                        {(job.duration_ms / 1000).toFixed(1)}s
                      </span>
                    )}
                  </button>

                  {expandedId === job.id && (
                    <div className="px-5 pb-4 bg-reap3r-surface/30 border-t border-reap3r-border/40 space-y-3 animate-fade-in">
                      {job.payload && (
                        <div>
                          <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1.5 mt-3">Payload</p>
                          <pre className="code-block text-[11px]">{JSON.stringify(job.payload, null, 2)}</pre>
                        </div>
                      )}
                      {job.result != null && (
                        <div>
                          <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1.5">Result</p>
                          <pre className="code-block text-[11px]">
                            {typeof job.result === 'string' ? job.result : JSON.stringify(job.result, null, 2)}
                          </pre>
                        </div>
                      )}
                      {job.error && (
                        <div>
                          <p className="text-[10px] font-bold text-reap3r-danger uppercase tracking-[0.12em] mb-1.5">Error</p>
                          <pre className="code-block text-[11px] !border-reap3r-danger/20 !text-reap3r-danger">{job.error}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {total > 25 && (
            <div className="flex items-center justify-between px-5 py-3 border-t border-reap3r-border/60">
              <span className="text-[10px] text-reap3r-muted font-mono">{total} total · page {page}</span>
              <div className="flex gap-1.5">
                <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Prev</Button>
                <Button variant="ghost" size="sm" disabled={jobs.length < 25} onClick={() => setPage(p => p + 1)}>Next →</Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
