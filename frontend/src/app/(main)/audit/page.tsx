'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Badge, Skeleton, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { ScrollText, User, Monitor, ShieldAlert } from 'lucide-react';

export default function AuditPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);

  useEffect(() => {
    api.audit.list({ page: String(page), limit: '50' }).then((res) => {
      setLogs(res.data);
      setTotal(res.total);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [page]);

  const actionBadgeVariant = (action: string) => {
    if (action.includes('delete') || action.includes('revoke')) return 'danger';
    if (action.includes('create') || action.includes('enroll')) return 'success';
    if (action.includes('job_')) return 'accent';
    return 'default';
  };

  return (
    <>
      <TopBar title="Audit Log" />
      <div className="p-6 space-y-4">
        <Card className="!p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-reap3r-border bg-reap3r-surface/50">
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Time</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Action</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Resource</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">User</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Agent</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">IP</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-reap3r-muted uppercase tracking-wider">Details</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(10)].map((_, i) => (
                  <tr key={i} className="border-b border-reap3r-border/50">
                    <td colSpan={7} className="px-4 py-3"><Skeleton className="h-6 w-full" /></td>
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr><td colSpan={7}><EmptyState icon={<ScrollText className="w-12 h-12" />} title="No audit logs" /></td></tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="border-b border-reap3r-border/50 hover:bg-reap3r-hover/50">
                    <td className="px-4 py-3 text-xs text-reap3r-muted whitespace-nowrap">{formatDate(log.created_at)}</td>
                    <td className="px-4 py-3"><Badge variant={actionBadgeVariant(log.action)}>{log.action}</Badge></td>
                    <td className="px-4 py-3 text-xs text-reap3r-text">{log.resource_type}{log.resource_id ? ` / ${log.resource_id.slice(0, 8)}` : ''}</td>
                    <td className="px-4 py-3 text-xs text-reap3r-muted font-mono">{log.user_id?.slice(0, 8) || '—'}</td>
                    <td className="px-4 py-3 text-xs text-reap3r-muted font-mono">{log.agent_id?.slice(0, 8) || '—'}</td>
                    <td className="px-4 py-3 text-xs text-reap3r-muted">{log.ip_address || '—'}</td>
                    <td className="px-4 py-3 text-xs text-reap3r-muted max-w-[200px] truncate">{log.details ? JSON.stringify(log.details) : '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}
