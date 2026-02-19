'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, Skeleton, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { ScrollText, Filter, RefreshCw, ChevronDown, ChevronRight, User, Monitor, Shield } from 'lucide-react';

const actionVariant = (a: string): 'default' | 'success' | 'danger' | 'accent' | 'warning' => {
  if (a.includes('delete') || a.includes('revoke') || a.includes('suspend')) return 'danger';
  if (a.includes('create') || a.includes('enroll') || a.includes('enable')) return 'success';
  if (a.includes('login') || a.includes('auth')) return 'accent';
  if (a.includes('update') || a.includes('change')) return 'warning';
  return 'default';
};

const actionIcon = (a: string) => {
  if (a.includes('user') || a.includes('login') || a.includes('role')) return <User style={{ width: '11px', height: '11px' }} />;
  if (a.includes('agent') || a.includes('enroll')) return <Monitor style={{ width: '11px', height: '11px' }} />;
  return <Shield style={{ width: '11px', height: '11px' }} />;
};

export default function AuditPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    api.audit.list({ page: String(page), limit: '50' })
      .then((res) => { setLogs(res.data); setTotal(res.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page]);

  useEffect(() => { load(); }, [load]);

  const filtered = logs.filter(log => {
    if (actionFilter && !log.action?.toLowerCase().includes(actionFilter.toLowerCase())) return false;
    if (resourceFilter && !log.resource_type?.toLowerCase().includes(resourceFilter.toLowerCase())) return false;
    return true;
  });

  return (
    <>
      <TopBar title="Audit Log" actions={
        <button onClick={load} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
          <RefreshCw style={{ width: '13px', height: '13px' }} />
        </button>
      } />
      <div className="p-6 space-y-4 animate-fade-in">
        {/* Filters */}
        <Card className="!py-3 !px-4 flex items-center gap-3 flex-wrap">
          <Filter className="text-reap3r-muted shrink-0" style={{ width: '12px', height: '12px' }} />
          <input
            placeholder="Filter by action..."
            value={actionFilter}
            onChange={e => setActionFilter(e.target.value)}
            className="px-3 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white
              placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 w-44"
          />
          <input
            placeholder="Filter by resource..."
            value={resourceFilter}
            onChange={e => setResourceFilter(e.target.value)}
            className="px-3 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-xs text-white
              placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 w-44"
          />
          <span className="text-[10px] text-reap3r-muted font-mono ml-auto">{total} events</span>
        </Card>

        {/* Log entries */}
        <Card className="!p-0 overflow-hidden">
          {loading ? (
            <div className="p-4 space-y-2">
              {[...Array(8)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState icon={<ScrollText style={{ width: '28px', height: '28px' }} />} title="No audit logs" description="System events will appear here as they occur." />
          ) : (
            <div className="divide-y divide-reap3r-border/40">
              {filtered.map(log => (
                <div key={log.id}>
                  <button
                    className="w-full flex items-center gap-4 px-5 py-3 hover:bg-reap3r-hover/40 transition-colors text-left group"
                    onClick={() => setExpandedId(expandedId === log.id ? null : log.id)}
                  >
                    <div className="shrink-0 text-reap3r-muted group-hover:text-reap3r-light transition-colors">
                      {expandedId === log.id
                        ? <ChevronDown style={{ width: '12px', height: '12px' }} />
                        : <ChevronRight style={{ width: '12px', height: '12px' }} />
                      }
                    </div>
                    <div className="w-8 h-8 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center text-reap3r-muted shrink-0">
                      {actionIcon(log.action || '')}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant={actionVariant(log.action)}>{log.action}</Badge>
                        <span className="text-[11px] text-reap3r-light">{log.resource_type}</span>
                        {log.resource_id && (
                          <span className="text-[10px] text-reap3r-muted font-mono">{log.resource_id.slice(0, 8)}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-0.5 text-[10px] text-reap3r-muted">
                        <span className="font-mono">{formatDate(log.created_at)}</span>
                        {log.ip_address && <span>IP: {log.ip_address}</span>}
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      {log.user_id && <p className="text-[10px] text-reap3r-muted font-mono">{log.user_id.slice(0, 8)}</p>}
                      {log.agent_id && <p className="text-[10px] text-reap3r-muted font-mono">{log.agent_id.slice(0, 8)}</p>}
                    </div>
                  </button>
                  {expandedId === log.id && (
                    <div className="px-5 pb-4 ml-16 animate-fade-in">
                      <div className="bg-reap3r-surface/40 border border-reap3r-border/60 rounded-xl p-4 space-y-2">
                        <div className="grid grid-cols-2 gap-3 text-[11px]">
                          <div>
                            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">User ID</p>
                            <p className="text-white font-mono mt-0.5">{log.user_id || '—'}</p>
                          </div>
                          <div>
                            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Agent ID</p>
                            <p className="text-white font-mono mt-0.5">{log.agent_id || '—'}</p>
                          </div>
                          <div>
                            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">IP Address</p>
                            <p className="text-white font-mono mt-0.5">{log.ip_address || '—'}</p>
                          </div>
                          <div>
                            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Resource</p>
                            <p className="text-white font-mono mt-0.5">{log.resource_type}{log.resource_id ? ` / ${log.resource_id}` : ''}</p>
                          </div>
                        </div>
                        {log.details && (
                          <div>
                            <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1">Details</p>
                            <pre className="code-block text-[11px]">{JSON.stringify(log.details, null, 2)}</pre>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {total > 50 && (
            <div className="flex items-center justify-between px-5 py-3 border-t border-reap3r-border/60">
              <span className="text-[10px] text-reap3r-muted font-mono">{total} total · page {page}</span>
              <div className="flex gap-1.5">
                <Button variant="ghost" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Prev</Button>
                <Button variant="ghost" size="sm" disabled={filtered.length < 50} onClick={() => setPage(p => p + 1)}>Next →</Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
