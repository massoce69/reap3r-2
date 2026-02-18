'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Badge, Button, Skeleton, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate, statusColor } from '@/lib/utils';
import { ListTodo, Search } from 'lucide-react';

export default function JobsPage() {
  const [jobs, setJobs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [expandedJob, setExpandedJob] = useState<string | null>(null);

  const fetchJobs = () => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), limit: '25', sort_order: 'desc' };
    if (statusFilter) params.status = statusFilter;
    if (typeFilter) params.type = typeFilter;

    api.jobs.list(params).then((res) => {
      setJobs(res.data);
      setTotal(res.total);
      setLoading(false);
    }).catch(() => setLoading(false));
  };

  useEffect(() => { fetchJobs(); }, [page, statusFilter, typeFilter]);

  return (
    <>
      <TopBar title="Jobs" />
      <div className="p-6 space-y-4">
        {/* Filters */}
        <Card className="flex items-center gap-4 !py-3 flex-wrap">
          <div className="flex gap-1">
            {['', 'pending', 'dispatched', 'running', 'completed', 'failed', 'cancelled'].map((s) => (
              <button
                key={s}
                onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  statusFilter === s
                    ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                    : 'text-reap3r-muted hover:text-reap3r-text hover:bg-reap3r-hover'
                }`}
              >
                {s || 'All'}
              </button>
            ))}
          </div>
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="px-3 py-1.5 text-xs bg-reap3r-surface border border-reap3r-border rounded-lg text-reap3r-text focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50"
          >
            <option value="">All Types</option>
            <option value="run_script">RunScript</option>
            <option value="reboot">Reboot</option>
            <option value="shutdown">Shutdown</option>
            <option value="service_action">Service Action</option>
            <option value="process_action">Process Action</option>
            <option value="collect_metrics">Collect Metrics</option>
            <option value="collect_inventory">Collect Inventory</option>
          </select>
          <span className="text-xs text-reap3r-muted ml-auto">{total} jobs total</span>
        </Card>

        {/* Jobs Table */}
        <Card className="!p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-reap3r-border bg-reap3r-surface/50">
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Type</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Agent</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Reason</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Created</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Completed</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i} className="border-b border-reap3r-border/50">
                    <td colSpan={6} className="px-4 py-3"><Skeleton className="h-6 w-full" /></td>
                  </tr>
                ))
              ) : jobs.length === 0 ? (
                <tr><td colSpan={6}><EmptyState icon={<ListTodo className="w-12 h-12" />} title="No jobs found" /></td></tr>
              ) : (
                jobs.map((job) => (
                  <>
                    <tr
                      key={job.id}
                      className="border-b border-reap3r-border/50 hover:bg-reap3r-hover/50 transition-colors cursor-pointer"
                      onClick={() => setExpandedJob(expandedJob === job.id ? null : job.id)}
                    >
                      <td className="px-4 py-3">
                        <Badge variant={job.status === 'success' ? 'success' : job.status === 'failed' ? 'danger' : job.status === 'running' ? 'accent' : job.status === 'timeout' ? 'warning' : 'default'}>
                          {job.status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-medium text-reap3r-text">{job.type}</td>
                      <td className="px-4 py-3 text-reap3r-muted font-mono text-xs">{job.agent_id?.slice(0, 8)}...</td>
                      <td className="px-4 py-3 text-reap3r-muted text-xs truncate max-w-[200px]">{job.reason || '—'}</td>
                      <td className="px-4 py-3 text-reap3r-muted text-xs">{formatDate(job.created_at)}</td>
                      <td className="px-4 py-3 text-reap3r-muted text-xs">{formatDate(job.completed_at)}</td>
                    </tr>
                    {expandedJob === job.id && (
                      <tr key={`${job.id}-detail`} className="border-b border-reap3r-border/50 bg-reap3r-surface/30">
                        <td colSpan={6} className="px-4 py-4">
                          <div className="grid grid-cols-2 gap-4 text-xs">
                            <div>
                              <p className="text-reap3r-muted mb-1">Payload</p>
                              <pre className="bg-reap3r-bg rounded-lg p-3 text-reap3r-text font-mono overflow-auto max-h-40">{JSON.stringify(job.payload, null, 2)}</pre>
                            </div>
                            <div>
                              <p className="text-reap3r-muted mb-1">Result</p>
                              <pre className="bg-reap3r-bg rounded-lg p-3 text-reap3r-text font-mono overflow-auto max-h-40">
                                {job.result ? JSON.stringify(job.result, null, 2) : job.error || 'No result yet'}
                              </pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))
              )}
            </tbody>
          </table>

          {total > 25 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-reap3r-border">
              <span className="text-xs text-reap3r-muted">Page {page}</span>
              <div className="flex gap-1">
                <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
                <Button variant="ghost" size="sm" disabled={jobs.length < 25} onClick={() => setPage(p => p + 1)}>Next</Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
