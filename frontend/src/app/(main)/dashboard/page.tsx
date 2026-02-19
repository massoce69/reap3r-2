'use client';
import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Badge, StatusDot, Skeleton } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import {
  Monitor, ListTodo, Bell, ShieldAlert,
  TrendingUp, ArrowUpRight, Clock, RefreshCw,
  Activity, Zap, AlertTriangle, CheckCircle,
  Building2, Download, Settings, ChevronRight,
} from 'lucide-react';

/* ── Types ── */
interface DashStats {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  degraded_agents: number;
  pending_agents: number;
  total_jobs: number;
  running_jobs: number;
  failed_jobs_24h: number;
  completed_jobs_24h: number;
  open_alerts: number;
  critical_alerts: number;
  open_detections: number;
}

/* ── Stat Card ── */
function StatCard({
  label, value, sub, icon: Icon, href, color = 'white', trend,
}: {
  label: string;
  value: number | string;
  sub?: string;
  icon: any;
  href?: string;
  color?: string;
  trend?: { value: number; label: string };
}) {
  const colorMap: Record<string, { text: string; bg: string; border: string }> = {
    white:   { text: 'text-white',              bg: 'bg-white/6',    border: 'border-white/10' },
    success: { text: 'text-reap3r-success',     bg: 'bg-reap3r-success/8', border: 'border-reap3r-success/15' },
    danger:  { text: 'text-reap3r-danger',      bg: 'bg-reap3r-danger/8',  border: 'border-reap3r-danger/15' },
    warning: { text: 'text-reap3r-warning',     bg: 'bg-reap3r-warning/8', border: 'border-reap3r-warning/15' },
  };
  const c = colorMap[color] ?? colorMap.white;

  const inner = (
    <div className="relative bg-reap3r-card border border-reap3r-border rounded-xl p-5 overflow-hidden
      hover:border-reap3r-border-light transition-all duration-200 group cursor-pointer
      shadow-[0_2px_12px_rgba(0,0,0,0.5)]">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/6 to-transparent" />
      <div className="flex items-start justify-between mb-4">
        <div className={`w-9 h-9 rounded-lg ${c.bg} border ${c.border} flex items-center justify-center shrink-0`}>
          <Icon className={c.text} style={{ width: '16px', height: '16px' }} />
        </div>
        {href && (
          <ArrowUpRight className="text-reap3r-muted/40 group-hover:text-reap3r-light transition-colors"
            style={{ width: '14px', height: '14px' }} />
        )}
      </div>
      <p className={`text-3xl font-black font-mono tracking-tight ${c.text}`}>{value}</p>
      <p className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] mt-1">{label}</p>
      {sub && <p className="text-[10px] text-reap3r-muted/60 mt-0.5">{sub}</p>}
    </div>
  );

  return href ? <Link href={href}>{inner}</Link> : inner;
}

/* ── Coverage Bar ── */
function CoverageBar({ online, total }: { online: number; total: number }) {
  const pct = total > 0 ? Math.round((online / total) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-1.5 bg-reap3r-subtle rounded-full overflow-hidden">
        <div
          className="h-full rounded-full bg-reap3r-success transition-all duration-700"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-bold font-mono text-reap3r-success w-10 text-right">{pct}%</span>
    </div>
  );
}

/* ── Quick Action ── */
function QuickAction({ href, icon: Icon, label }: { href: string; icon: any; label: string }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-3 px-4 py-3 bg-reap3r-hover border border-reap3r-border rounded-xl
        hover:border-reap3r-border-light hover:bg-reap3r-subtle transition-all duration-150 group"
    >
      <Icon className="text-reap3r-muted group-hover:text-white transition-colors shrink-0"
        style={{ width: '14px', height: '14px' }} />
      <span className="text-[11px] font-semibold text-reap3r-muted group-hover:text-white transition-colors uppercase tracking-[0.06em]">
        {label}
      </span>
      <ChevronRight className="text-reap3r-muted/30 group-hover:text-reap3r-light ml-auto transition-colors"
        style={{ width: '12px', height: '12px' }} />
    </Link>
  );
}

/* ── Main Page ── */
export default function DashboardPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState<DashStats | null>(null);
  const [recentAgents, setRecentAgents] = useState<any[]>([]);
  const [recentJobs, setRecentJobs] = useState<any[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [dashRes, agentsRes, jobsRes, alertsRes] = await Promise.allSettled([
        (api as any).dashboard?.stats ? (api as any).dashboard.stats() : Promise.resolve(null),
        api.agents.list({ limit: '8', sort: 'last_seen_at' }),
        api.jobs.list({ limit: '6', sort: 'created_at' }),
        (api as any).alerts?.events?.list ? (api as any).alerts.events.list({ limit: '5', status: 'open' }) : Promise.resolve({ data: [] }),
      ]);

      if (dashRes.status === 'fulfilled' && dashRes.value) {
        setStats(dashRes.value);
      } else if (agentsRes.status === 'fulfilled') {
        const agents = agentsRes.value?.data ?? [];
        const online = agents.filter((a: any) => a.status === 'online').length;
        setStats({
          total_agents: agentsRes.value?.total ?? agents.length,
          online_agents: online,
          offline_agents: agents.filter((a: any) => a.status === 'offline').length,
          degraded_agents: agents.filter((a: any) => a.status === 'degraded').length,
          pending_agents: agents.filter((a: any) => a.status === 'pending').length,
          total_jobs: jobsRes.status === 'fulfilled' ? (jobsRes.value?.total ?? 0) : 0,
          running_jobs: 0,
          failed_jobs_24h: 0,
          completed_jobs_24h: 0,
          open_alerts: alertsRes.status === 'fulfilled' ? (alertsRes.value?.total ?? 0) : 0,
          critical_alerts: 0,
          open_detections: 0,
        });
      }

      if (agentsRes.status === 'fulfilled') setRecentAgents(agentsRes.value?.data ?? []);
      if (jobsRes.status === 'fulfilled') setRecentJobs(jobsRes.value?.data ?? []);
      if (alertsRes.status === 'fulfilled') setRecentAlerts(alertsRes.value?.data ?? []);
    } catch {}
    setLoading(false);
    setLastRefresh(new Date());
  }, []);

  useEffect(() => { load(); }, [load]);

  const statCards = stats ? [
    {
      label: 'Agents Online',
      value: stats.online_agents,
      sub: `${stats.total_agents} total`,
      icon: Monitor,
      href: '/agents',
      color: stats.online_agents > 0 ? 'success' : 'white',
    },
    {
      label: 'Active Jobs',
      value: stats.running_jobs,
      sub: `${stats.completed_jobs_24h} done today`,
      icon: ListTodo,
      href: '/jobs',
      color: 'white',
    },
    {
      label: 'Open Alerts',
      value: stats.open_alerts,
      sub: `${stats.critical_alerts} critical`,
      icon: Bell,
      href: '/alerting',
      color: stats.open_alerts > 0 ? 'warning' : 'white',
    },
    {
      label: 'EDR Detections',
      value: stats.open_detections,
      sub: 'Unresolved',
      icon: ShieldAlert,
      href: '/edr',
      color: stats.open_detections > 0 ? 'danger' : 'white',
    },
  ] : [];

  const jobStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-reap3r-success';
      case 'failed': return 'text-reap3r-danger';
      case 'running': return 'text-white';
      default: return 'text-reap3r-muted';
    }
  };

  return (
    <>
      <TopBar
        title="Dashboard"
        actions={
          <div className="flex items-center gap-3">
            <span className="text-[10px] text-reap3r-muted font-mono flex items-center gap-1.5">
              <Clock style={{ width: '10px', height: '10px' }} />
              {lastRefresh.toLocaleTimeString()}
            </span>
            <button
              onClick={load}
              className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"
              title="Refresh"
            >
              <RefreshCw style={{ width: '13px', height: '13px' }} />
            </button>
          </div>
        }
      />

      <div className="p-6 space-y-6 animate-fade-in">

        {/* Welcome */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">
              Welcome back{user?.name ? `, ${user.name}` : ''}
            </h2>
            <p className="text-xs text-reap3r-muted mt-0.5">
              {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
            </p>
          </div>
          {stats && (
            <div className="hidden md:flex items-center gap-2 px-3 py-2 bg-reap3r-card border border-reap3r-border rounded-xl">
              <Activity className="text-reap3r-success" style={{ width: '13px', height: '13px' }} />
              <span className="text-[11px] font-semibold text-reap3r-success">System Operational</span>
            </div>
          )}
        </div>

        {/* KPI Stats */}
        {loading ? (
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl p-5">
                <Skeleton className="h-9 w-9 rounded-lg mb-4" />
                <Skeleton className="h-8 w-16 mb-2" />
                <Skeleton className="h-3 w-24" />
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            {statCards.map((card) => (
              <StatCard key={card.label} {...card} />
            ))}
          </div>
        )}

        {/* Coverage */}
        {stats && (
          <Card className="!py-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Zap className="text-reap3r-light" style={{ width: '13px', height: '13px' }} />
                <span className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Agent Coverage</span>
              </div>
              <span className="text-[10px] text-reap3r-muted font-mono">
                {stats.online_agents} / {stats.total_agents} online
              </span>
            </div>
            <CoverageBar online={stats.online_agents} total={stats.total_agents} />
            <div className="flex gap-4 mt-3">
              {[
                { label: 'Online', count: stats.online_agents, color: 'text-reap3r-success' },
                { label: 'Offline', count: stats.offline_agents, color: 'text-reap3r-muted' },
                { label: 'Degraded', count: stats.degraded_agents, color: 'text-reap3r-warning' },
                { label: 'Pending', count: stats.pending_agents, color: 'text-white/60' },
              ].map((s) => (
                <div key={s.label} className="flex items-center gap-1.5">
                  <span className={`text-xs font-bold font-mono ${s.color}`}>{s.count}</span>
                  <span className="text-[10px] text-reap3r-muted uppercase tracking-wider">{s.label}</span>
                </div>
              ))}
            </div>
          </Card>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Recent Agents */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                <Monitor style={{ width: '11px', height: '11px' }} />
                Recent Agents
              </h3>
              <Link href="/agents" className="text-[10px] text-reap3r-muted hover:text-white transition-colors flex items-center gap-1">
                View all <ChevronRight style={{ width: '10px', height: '10px' }} />
              </Link>
            </div>
            <Card className="!p-0 overflow-hidden">
              {loading ? (
                <div className="p-4 space-y-3">
                  {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
                </div>
              ) : recentAgents.length === 0 ? (
                <div className="py-10 text-center">
                  <p className="text-xs text-reap3r-muted">No agents found.</p>
                  <Link href="/deployment" className="text-[11px] text-white/60 hover:text-white mt-2 inline-block">
                    Deploy your first agent →
                  </Link>
                </div>
              ) : (
                <div className="divide-y divide-reap3r-border/50">
                  {recentAgents.map((agent) => (
                    <Link
                      key={agent.id}
                      href={`/agents/${agent.id}`}
                      className="flex items-center gap-3 px-5 py-3 hover:bg-reap3r-hover/50 transition-colors group"
                    >
                      <StatusDot status={agent.status} />
                      <div className="flex-1 min-w-0">
                        <p className="text-[12px] font-semibold text-white truncate group-hover:text-white/90">
                          {agent.hostname}
                        </p>
                        <p className="text-[10px] text-reap3r-muted font-mono truncate">
                          {agent.os} {agent.arch} · {agent.ip_address}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {agent.tags?.slice(0, 1).map((tag: string) => (
                          <Badge key={tag} variant="default">{tag}</Badge>
                        ))}
                        <span className="text-[10px] text-reap3r-muted font-mono capitalize">{agent.status}</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </Card>
          </div>

          {/* Right column: Quick Actions + Recent Jobs */}
          <div className="space-y-6">

            {/* Quick Actions */}
            <div className="space-y-3">
              <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                <Zap style={{ width: '11px', height: '11px' }} />
                Quick Actions
              </h3>
              <div className="space-y-1.5">
                <QuickAction href="/deployment" icon={Download} label="Deploy Agent" />
                <QuickAction href="/jobs" icon={ListTodo} label="View Jobs" />
                <QuickAction href="/alerting/rules" icon={Bell} label="Alert Rules" />
                <QuickAction href="/edr" icon={ShieldAlert} label="EDR / SOC" />
                <QuickAction href="/settings" icon={Settings} label="Settings" />
              </div>
            </div>

            {/* Recent Jobs */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                  <ListTodo style={{ width: '11px', height: '11px' }} />
                  Recent Jobs
                </h3>
                <Link href="/jobs" className="text-[10px] text-reap3r-muted hover:text-white transition-colors">
                  View all →
                </Link>
              </div>
              <Card className="!p-0 overflow-hidden">
                {loading ? (
                  <div className="p-3 space-y-2">
                    {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-7" />)}
                  </div>
                ) : recentJobs.length === 0 ? (
                  <p className="text-xs text-reap3r-muted p-4 text-center">No jobs yet.</p>
                ) : (
                  <div className="divide-y divide-reap3r-border/50">
                    {recentJobs.map((job) => (
                      <div key={job.id} className="flex items-center gap-3 px-4 py-2.5">
                        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                          job.status === 'completed' ? 'bg-reap3r-success' :
                          job.status === 'failed' ? 'bg-reap3r-danger' :
                          job.status === 'running' ? 'bg-white' : 'bg-reap3r-muted'
                        }`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] font-medium text-white/80 truncate">{job.type}</p>
                          <p className="text-[10px] text-reap3r-muted font-mono truncate">
                            {new Date(job.created_at).toLocaleTimeString()}
                          </p>
                        </div>
                        <span className={`text-[10px] font-semibold capitalize font-mono ${jobStatusColor(job.status)}`}>
                          {job.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          </div>
        </div>

        {/* Recent Alerts */}
        {recentAlerts.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                <AlertTriangle style={{ width: '11px', height: '11px' }} />
                Open Alerts
              </h3>
              <Link href="/alerting" className="text-[10px] text-reap3r-muted hover:text-white transition-colors">
                View all →
              </Link>
            </div>
            <div className="space-y-1.5">
              {recentAlerts.map((alert) => (
                <Link
                  key={alert.id}
                  href="/alerting"
                  className="flex items-center gap-4 px-5 py-3 bg-reap3r-card border border-reap3r-border rounded-xl
                    hover:border-reap3r-border-light transition-all duration-150"
                >
                  <AlertTriangle
                    className={alert.severity === 'critical' || alert.severity === 'high' ? 'text-reap3r-danger' : 'text-reap3r-warning'}
                    style={{ width: '13px', height: '13px', flexShrink: 0 }}
                  />
                  <p className="flex-1 text-[12px] font-medium text-white truncate">{alert.title}</p>
                  <Badge variant={alert.severity === 'critical' || alert.severity === 'high' ? 'danger' : 'warning'}>
                    {alert.severity}
                  </Badge>
                  <span className="text-[10px] text-reap3r-muted font-mono shrink-0">
                    {new Date(alert.created_at).toLocaleTimeString()}
                  </span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
