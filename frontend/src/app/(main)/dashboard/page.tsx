'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Skeleton, Badge, StatusDot } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { Monitor, ListTodo, CheckCircle, AlertTriangle, Activity, Clock } from 'lucide-react';
import Link from 'next/link';

interface DashboardData {
  agents: { data: any[]; total: number };
  jobs: { data: any[]; total: number };
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.agents.list({ limit: '5' }),
      api.jobs.list({ limit: '10', sort_order: 'desc' }),
    ]).then(([agents, jobs]) => {
      setData({ agents, jobs });
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const agentsOnline = data?.agents.data.filter((a) => a.status === 'online').length ?? 0;
  const agentsTotal = data?.agents.total ?? 0;
  const jobsSuccess = data?.jobs.data.filter((j) => j.status === 'success').length ?? 0;
  const jobsFailed = data?.jobs.data.filter((j) => j.status === 'failed').length ?? 0;

  return (
    <>
      <TopBar title="Dashboard" />
      <div className="p-6 space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon={<Monitor className="w-5 h-5" />} label="Agents Online" value={loading ? '—' : `${agentsOnline}/${agentsTotal}`} color="accent" />
          <StatCard icon={<Activity className="w-5 h-5" />} label="Running Jobs" value={loading ? '—' : `${data?.jobs.data.filter(j => j.status === 'running').length ?? 0}`} color="accent" />
          <StatCard icon={<CheckCircle className="w-5 h-5" />} label="Jobs Succeeded" value={loading ? '—' : `${jobsSuccess}`} color="success" />
          <StatCard icon={<AlertTriangle className="w-5 h-5" />} label="Jobs Failed" value={loading ? '—' : `${jobsFailed}`} color="danger" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Agents */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text">Recent Agents</h3>
              <Link href="/agents" className="text-xs text-reap3r-accent hover:underline">View All</Link>
            </div>
            {loading ? (
              <div className="space-y-3">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
            ) : (
              <div className="divide-y divide-reap3r-border">
                {data?.agents.data.map((agent) => (
                  <Link key={agent.id} href={`/agents/${agent.id}`} className="flex items-center gap-3 py-3 hover:bg-reap3r-hover px-2 -mx-2 rounded-lg transition-colors">
                    <StatusDot status={agent.status} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-reap3r-text truncate">{agent.hostname}</p>
                      <p className="text-xs text-reap3r-muted">{agent.os} • {agent.arch}</p>
                    </div>
                    <span className="text-xs text-reap3r-muted">{formatDate(agent.last_seen_at)}</span>
                  </Link>
                ))}
                {data?.agents.data.length === 0 && (
                  <p className="text-sm text-reap3r-muted py-4 text-center">No agents enrolled yet.</p>
                )}
              </div>
            )}
          </Card>

          {/* Recent Jobs */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text">Recent Jobs</h3>
              <Link href="/jobs" className="text-xs text-reap3r-accent hover:underline">View All</Link>
            </div>
            {loading ? (
              <div className="space-y-3">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
            ) : (
              <div className="divide-y divide-reap3r-border">
                {data?.jobs.data.map((job) => (
                  <div key={job.id} className="flex items-center gap-3 py-3">
                    <Clock className="w-4 h-4 text-reap3r-muted" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-reap3r-text">{job.type}</p>
                      <p className="text-xs text-reap3r-muted">{formatDate(job.created_at)}</p>
                    </div>
                    <Badge variant={job.status === 'success' ? 'success' : job.status === 'failed' ? 'danger' : job.status === 'running' ? 'accent' : 'default'}>
                      {job.status}
                    </Badge>
                  </div>
                ))}
                {data?.jobs.data.length === 0 && (
                  <p className="text-sm text-reap3r-muted py-4 text-center">No jobs yet.</p>
                )}
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
  const colors: Record<string, string> = {
    accent: 'text-reap3r-accent bg-reap3r-accent/10',
    success: 'text-reap3r-success bg-reap3r-success/10',
    danger: 'text-reap3r-danger bg-reap3r-danger/10',
    warning: 'text-reap3r-warning bg-reap3r-warning/10',
  };
  return (
    <Card className="flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${colors[color]}`}>
        {icon}
      </div>
      <div>
        <p className="text-2xl font-bold text-reap3r-text">{value}</p>
        <p className="text-xs text-reap3r-muted">{label}</p>
      </div>
    </Card>
  );
}
