'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Skeleton, Badge, StatusDot } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { useRealtimeClient } from '@/lib/ws';
import {
  Monitor, ListTodo, CheckCircle, AlertTriangle, Activity, Clock,
  Shield, Lock, Cpu, HardDrive, Bell, Eye, ShieldAlert, Users,
} from 'lucide-react';
import Link from 'next/link';

interface DashboardData {
  agents: { data: any[]; total: number };
  agentStats: any;
  jobs: { data: any[]; total: number };
  jobStats: any;
  alertStats: any;
  edrDetections: { data: any[]; total: number };
  edrIncidents: { data: any[]; total: number };
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const ws = useRealtimeClient();

  const loadData = useCallback(() => {
    Promise.all([
      api.agents.list({ limit: '8', sort_by: 'last_seen_at', sort_order: 'desc' }),
      api.agents.stats().catch(() => null),
      api.jobs.list({ limit: '10', sort_order: 'desc' }),
      api.jobs.stats().catch(() => null),
      api.alerts.stats().catch(() => null),
      api.edr.detections({ limit: '5', status: 'open' }).catch(() => ({ data: [], total: 0 })),
      api.edr.incidents({ limit: '5', status: 'open' }).catch(() => ({ data: [], total: 0 })),
    ]).then(([agents, agentStats, jobs, jobStats, alertStats, edrDetections, edrIncidents]) => {
      setData({ agents, agentStats, jobs, jobStats, alertStats, edrDetections, edrIncidents });
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // Real-time updates
  useEffect(() => {
    if (!ws) return;
    const handleUpdate = () => {
      // Debounce re-fetch on WS events
      const timer = setTimeout(loadData, 2000);
      return () => clearTimeout(timer);
    };
    const unsub1 = ws.on('agent_online', handleUpdate);
    const unsub2 = ws.on('agent_offline', handleUpdate);
    const unsub3 = ws.on('job_update', handleUpdate);
    const unsub4 = ws.on('alert_event', handleUpdate);
    return () => {
      unsub1(); unsub2(); unsub3(); unsub4();
    };
  }, [ws, loadData]);

  const stats = data?.agentStats;
  const jStats = data?.jobStats;
  const aStats = data?.alertStats;

  const agentsOnline = stats?.online ?? data?.agents.data.filter((a) => a.status === 'online').length ?? 0;
  const agentsTotal = stats?.total ?? data?.agents.total ?? 0;
  const agentsOffline = stats?.offline ?? 0;
  const agentsIsolated = stats?.isolated ?? 0;

  const jobsRunning = jStats?.running ?? data?.jobs.data.filter(j => j.status === 'running').length ?? 0;
  const jobsSuccess = jStats?.success ?? data?.jobs.data.filter((j) => j.status === 'success').length ?? 0;
  const jobsFailed = jStats?.failed ?? data?.jobs.data.filter((j) => j.status === 'failed').length ?? 0;

  const alertsOpen = aStats?.open ?? 0;
  const alertsCritical = aStats?.critical ?? 0;

  const edrOpenDetections = data?.edrDetections?.total ?? 0;
  const edrOpenIncidents = data?.edrIncidents?.total ?? 0;

  return (
    <>
      <TopBar title="Dashboard" />
      <div className="p-6 space-y-6">
        {/* Primary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
          <StatCard icon={<Monitor className="w-4 h-4" />} label="Agents" value={loading ? '—' : `${agentsOnline}/${agentsTotal}`} sublabel="online" color="accent" />
          <StatCard icon={<Activity className="w-4 h-4" />} label="Offline" value={loading ? '—' : `${agentsOffline}`} color="warning" />
          <StatCard icon={<Lock className="w-4 h-4" />} label="Isolated" value={loading ? '—' : `${agentsIsolated}`} color="danger" />
          <StatCard icon={<Cpu className="w-4 h-4" />} label="Running" value={loading ? '—' : `${jobsRunning}`} sublabel="jobs" color="accent" />
          <StatCard icon={<CheckCircle className="w-4 h-4" />} label="Success" value={loading ? '—' : `${jobsSuccess}`} color="success" />
          <StatCard icon={<AlertTriangle className="w-4 h-4" />} label="Failed" value={loading ? '—' : `${jobsFailed}`} color="danger" />
          <StatCard icon={<Bell className="w-4 h-4" />} label="Alerts" value={loading ? '—' : `${alertsOpen}`} sublabel="open" color="warning" />
          <StatCard icon={<ShieldAlert className="w-4 h-4" />} label="EDR" value={loading ? '—' : `${edrOpenDetections}`} sublabel="detections" color="danger" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Recent Agents */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2">
                <Monitor className="w-4 h-4 text-reap3r-accent" />
                Agents
              </h3>
              <Link href="/agents" className="text-xs text-reap3r-accent hover:underline">View All</Link>
            </div>
            {loading ? (
              <div className="space-y-3">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
            ) : (
              <div className="divide-y divide-reap3r-border">
                {data?.agents.data.map((agent) => (
                  <Link key={agent.id} href={`/agents/${agent.id}`} className="flex items-center gap-3 py-2.5 hover:bg-reap3r-hover px-2 -mx-2 rounded-lg transition-colors">
                    <StatusDot status={agent.status} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-reap3r-text truncate">{agent.hostname}</p>
                      <p className="text-xs text-reap3r-muted">{agent.os} • {agent.arch}</p>
                    </div>
                    <div className="text-right">
                      {agent.cpu_percent > 0 && (
                        <p className="text-xs text-reap3r-muted">CPU {Math.round(agent.cpu_percent)}%</p>
                      )}
                      <span className="text-xs text-reap3r-muted">{formatDate(agent.last_seen_at)}</span>
                    </div>
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
              <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2">
                <ListTodo className="w-4 h-4 text-reap3r-accent" />
                Recent Jobs
              </h3>
              <Link href="/jobs" className="text-xs text-reap3r-accent hover:underline">View All</Link>
            </div>
            {loading ? (
              <div className="space-y-3">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
            ) : (
              <div className="divide-y divide-reap3r-border">
                {data?.jobs.data.map((job) => (
                  <div key={job.id} className="flex items-center gap-3 py-2.5">
                    <Clock className="w-4 h-4 text-reap3r-muted shrink-0" />
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

          {/* Security Overview */}
          <div className="space-y-6">
            {/* Open Alerts */}
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2">
                  <Bell className="w-4 h-4 text-reap3r-warning" />
                  Open Alerts
                </h3>
                <Link href="/alerting" className="text-xs text-reap3r-accent hover:underline">View All</Link>
              </div>
              {loading ? (
                <Skeleton className="h-12 w-full" />
              ) : alertsOpen === 0 ? (
                <div className="flex items-center gap-2 text-sm text-reap3r-success">
                  <CheckCircle className="w-4 h-4" />
                  No open alerts
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-reap3r-text">Open alerts</span>
                    <Badge variant="warning">{alertsOpen}</Badge>
                  </div>
                  {alertsCritical > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-reap3r-danger">Critical</span>
                      <Badge variant="danger">{alertsCritical}</Badge>
                    </div>
                  )}
                </div>
              )}
            </Card>

            {/* EDR Status */}
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-reap3r-danger" />
                  EDR Status
                </h3>
                <Link href="/edr" className="text-xs text-reap3r-accent hover:underline">View All</Link>
              </div>
              {loading ? (
                <Skeleton className="h-12 w-full" />
              ) : edrOpenDetections === 0 && edrOpenIncidents === 0 ? (
                <div className="flex items-center gap-2 text-sm text-reap3r-success">
                  <Shield className="w-4 h-4" />
                  No open threats
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-reap3r-text">Open detections</span>
                    <Badge variant="warning">{edrOpenDetections}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-reap3r-text">Open incidents</span>
                    <Badge variant="danger">{edrOpenIncidents}</Badge>
                  </div>
                </div>
              )}
            </Card>

            {/* Quick Stats */}
            <Card>
              <h3 className="text-sm font-semibold text-reap3r-text flex items-center gap-2 mb-3">
                <Eye className="w-4 h-4 text-reap3r-accent" />
                Platform Health
              </h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-reap3r-muted">Agent coverage</span>
                  <span className="text-reap3r-text font-medium">
                    {agentsTotal > 0 ? `${Math.round((agentsOnline / agentsTotal) * 100)}%` : '—'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-reap3r-muted">Job success rate</span>
                  <span className="text-reap3r-text font-medium">
                    {(jobsSuccess + jobsFailed) > 0 ? `${Math.round((jobsSuccess / (jobsSuccess + jobsFailed)) * 100)}%` : '—'}
                  </span>
                </div>
              </div>
            </Card>
          </div>
        </div>
      </div>
    </>
  );
}

function StatCard({ icon, label, value, sublabel, color }: { icon: React.ReactNode; label: string; value: string; sublabel?: string; color: string }) {
  const colors: Record<string, string> = {
    accent: 'text-reap3r-accent bg-reap3r-accent/10',
    success: 'text-reap3r-success bg-reap3r-success/10',
    danger: 'text-reap3r-danger bg-reap3r-danger/10',
    warning: 'text-reap3r-warning bg-reap3r-warning/10',
  };
  return (
    <Card className="!p-4">
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-2 ${colors[color]}`}>
        {icon}
      </div>
      <p className="text-xl font-bold text-reap3r-text">{value}</p>
      <p className="text-xs text-reap3r-muted">{label}{sublabel ? ` ${sublabel}` : ''}</p>
    </Card>
  );
}
