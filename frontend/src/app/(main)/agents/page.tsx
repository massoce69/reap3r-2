'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Input, Badge, StatusDot, EmptyState, Skeleton } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate, statusColor } from '@/lib/utils';
import { Monitor, Search, Filter } from 'lucide-react';

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);

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

  useEffect(() => { fetchAgents(); }, [page, statusFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAgents();
  };

  return (
    <>
      <TopBar title="Agents" actions={
        <Link href="/deployment">
          <Button size="sm">Deploy Agent</Button>
        </Link>
      } />
      <div className="p-6 space-y-4">
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
                    <td colSpan={6} className="px-4 py-3"><Skeleton className="h-6 w-full" /></td>
                  </tr>
                ))
              ) : agents.length === 0 ? (
                <tr><td colSpan={6}><EmptyState icon={<Monitor className="w-12 h-12" />} title="No agents found" description="Deploy your first agent to get started." /></td></tr>
              ) : (
                agents.map((agent) => (
                  <tr key={agent.id} className="border-b border-reap3r-border/50 hover:bg-reap3r-hover/50 transition-colors cursor-pointer">
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
                    <td className="px-4 py-3"><Badge>{agent.agent_version}</Badge></td>
                    <td className="px-4 py-3 text-reap3r-muted text-xs">{formatDate(agent.last_seen_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1 flex-wrap">
                        {agent.tags?.map((tag: string) => <Badge key={tag} variant="accent">{tag}</Badge>)}
                      </div>
                    </td>
                  </tr>
                ))
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
