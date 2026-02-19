'use client';
import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Badge, StatusDot, Skeleton } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { useRealtimeRefresh, WS_ALL_EVENTS } from '@/hooks/useRealtimeData';
import {
  Monitor, ListTodo, Bell, ShieldAlert,
  ArrowUpRight, Clock, RefreshCw,
  Activity, Zap, AlertTriangle,
  Download, Settings, ChevronRight,
  PieChart, BarChart3,
} from 'lucide-react';

/* ── Types ── */
interface DashStats {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  isolated_agents: number;
  by_os: Record<string, number>;
  total_jobs: number;
  running_jobs: number;
  pending_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  open_alerts: number;
  critical_alerts: number;
  acked_alerts: number;
  open_detections: number;
  total_companies: number;
}

/* ── Stat Card ── */
function StatCard({ label, value, sub, icon: Icon, href, color = 'white' }: {
  label: string; value: number | string; sub?: string; icon: any; href?: string; color?: string;
}) {
  const colorMap: Record<string, { text: string; bg: string; border: string }> = {
    white:   { text: 'text-white',          bg: 'bg-white/6',             border: 'border-white/10' },
    success: { text: 'text-reap3r-success', bg: 'bg-reap3r-success/8',    border: 'border-reap3r-success/15' },
    danger:  { text: 'text-reap3r-danger',  bg: 'bg-reap3r-danger/8',     border: 'border-reap3r-danger/15' },
    warning: { text: 'text-reap3r-warning', bg: 'bg-reap3r-warning/8',    border: 'border-reap3r-warning/15' },
    cyan:    { text: 'text-cyan-400',       bg: 'bg-cyan-400/8',          border: 'border-cyan-400/15' },
  };
  const c = colorMap[color] ?? colorMap.white;
  const inner = (
    <div className="relative bg-reap3r-card border border-reap3r-border rounded-xl p-5 overflow-hidden hover:border-reap3r-border-light transition-all duration-200 group cursor-pointer shadow-[0_2px_12px_rgba(0,0,0,0.5)]">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/6 to-transparent" />
      <div className="flex items-start justify-between mb-4">
        <div className={`w-9 h-9 rounded-lg ${c.bg} border ${c.border} flex items-center justify-center shrink-0`}>
          <Icon className={c.text} style={{ width: '16px', height: '16px' }} />
        </div>
        {href && <ArrowUpRight className="text-reap3r-muted/40 group-hover:text-reap3r-light transition-colors" style={{ width: '14px', height: '14px' }} />}
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
        <div className="h-full rounded-full bg-reap3r-success transition-all duration-700" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-bold font-mono text-reap3r-success w-10 text-right">{pct}%</span>
    </div>
  );
}

/* ── OS Distribution ── */
function OsDistribution({ data }: { data: Record<string, number> }) {
  const total = Object.values(data).reduce((s, v) => s + v, 0);
  if (total === 0) return <p className="text-xs text-reap3r-muted text-center py-2">No agents</p>;
  const items = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const colors: Record<string, string> = { windows: 'bg-blue-500', linux: 'bg-orange-500', macos: 'bg-white/70', other: 'bg-purple-500' };
  return (
    <div className="space-y-2">
      <div className="flex h-2 rounded-full overflow-hidden bg-reap3r-subtle">
        {items.map(([os, count]) => (
          <div key={os} className={`${colors[os] || 'bg-gray-500'} transition-all duration-500`} style={{ width: `${(count / total) * 100}%` }} />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {items.map(([os, count]) => (
          <div key={os} className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${colors[os] || 'bg-gray-500'}`} />
            <span className="text-[10px] text-reap3r-muted capitalize">{os}</span>
            <span className="text-[10px] font-bold font-mono text-white/70">{count}</span>
            <span className="text-[10px] text-reap3r-muted/50">({Math.round((count / total) * 100)}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Mini Bar Chart ── */
function MiniBarChart({ completed, failed, running, pending }: { completed: number; failed: number; running: number; pending: number }) {
  const total = completed + failed + running + pending;
  if (total === 0) return <p className="text-xs text-reap3r-muted text-center py-2">No jobs data</p>;
  const bars = [
    { label: 'Completed', value: completed, color: 'bg-reap3r-success' },
    { label: 'Failed', value: failed, color: 'bg-reap3r-danger' },
    { label: 'Running', value: running, color: 'bg-white' },
    { label: 'Pending', value: pending, color: 'bg-reap3r-muted' },
  ];
  const max = Math.max(...bars.map(b => b.value), 1);
  return (
    <div className="flex items-end gap-2 h-16">
      {bars.map((b) => (
        <div key={b.label} className="flex-1 flex flex-col items-center gap-1">
          <span className="text-[9px] font-mono font-bold text-white/60">{b.value}</span>
          <div className="w-full relative rounded-t" style={{ height: `${Math.max((b.value / max) * 48, 2)}px` }}>
            <div className={`absolute inset-0 ${b.color} rounded-t opacity-80`} />
          </div>
          <span className="text-[8px] text-reap3r-muted uppercase tracking-wider truncate w-full text-center">{b.label}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Quick Action ── */
function QuickAction({ href, icon: Icon, label }: { href: string; icon: any; label: string }) {
  return (
    <Link href={href} className="flex items-center gap-3 px-4 py-3 bg-reap3r-hover border border-reap3r-border rounded-xl hover:border-reap3r-border-light hover:bg-reap3r-subtle transition-all duration-150 group">
      <Icon className="text-reap3r-muted group-hover:text-white transition-colors shrink-0" style={{ width: '14px', height: '14px' }} />
      <span className="text-[11px] font-semibold text-reap3r-muted group-hover:text-white transition-colors uppercase tracking-[0.06em]">{label}</span>
      <ChevronRight className="text-reap3r-muted/30 group-hover:text-reap3r-light ml-auto transition-colors" style={{ width: '12px', height: '12px' }} />
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
    try {
      const [agentStatsRes, jobStatsRes, alertStatsRes, agentsRes, jobsRes, alertsRes, companiesRes, edrRes] = await Promise.allSettled([
        api.agents.stats(),
        api.jobs.stats(),
        api.alerts.stats(),
        api.agents.list({ limit: '10', sort_by: 'last_seen_at', sort_dir: 'desc' }),
        api.jobs.list({ limit: '8' }),
        api.alerts.events.list({ limit: '5', status: 'open' }),
        api.companies.list({ limit: '1' }),
        api.edr.detections({ limit: '1' }),
      ]);
      const agentStats = agentStatsRes.status === 'fulfilled' ? agentStatsRes.value : null;
      const jobStats = jobStatsRes.status === 'fulfilled' ? jobStatsRes.value : null;
      const alertStats = alertStatsRes.status === 'fulfilled' ? alertStatsRes.value : null;
      setStats({
        total_agents: agentStats?.total ?? 0,
        online_agents: agentStats?.online ?? 0,
        offline_agents: agentStats?.offline ?? 0,
        isolated_agents: agentStats?.isolated ?? 0,
        by_os: agentStats?.by_os ?? {},
        total_jobs: jobStats?.total ?? 0,
        running_jobs: jobStats?.running ?? 0,
        pending_jobs: jobStats?.pending ?? 0,
        completed_jobs: jobStats?.completed ?? 0,
        failed_jobs: jobStats?.failed ?? 0,
        open_alerts: alertStats?.open ?? 0,
        critical_alerts: alertStats?.critical ?? 0,
        acked_alerts: alertStats?.acknowledged ?? 0,
        open_detections: edrRes.status === 'fulfilled' ? (edrRes.value as any)?.total ?? 0 : 0,
        total_companies: companiesRes.status === 'fulfilled' ? (companiesRes.value as any)?.total ?? 0 : 0,
      });
      if (agentsRes.status === 'fulfilled') setRecentAgents(agentsRes.value?.data ?? []);
      if (jobsRes.status === 'fulfilled') setRecentJobs(jobsRes.value?.data ?? []);
      if (alertsRes.status === 'fulfilled') setRecentAlerts(alertsRes.value?.data ?? []);
    } catch {}
    setLoading(false);
    setLastRefresh(new Date());
  }, []);

  useEffect(() => { load(); }, [load]);
  useRealtimeRefresh(WS_ALL_EVENTS, load, 3000);

  const statCards = stats ? [
    { label: 'Agents Online', value: stats.online_agents, sub: `${stats.total_agents} total · ${stats.isolated_agents} isolated`, icon: Monitor, href: '/agents', color: stats.online_agents > 0 ? 'success' : 'white' },
    { label: 'Active Jobs', value: stats.running_jobs + stats.pending_jobs, sub: `${stats.completed_jobs} done · ${stats.failed_jobs} failed`, icon: ListTodo, href: '/jobs', color: stats.running_jobs > 0 ? 'cyan' : 'white' },
    { label: 'Open Alerts', value: stats.open_alerts, sub: `${stats.critical_alerts} critical · ${stats.acked_alerts} acked`, icon: Bell, href: '/alerting', color: stats.critical_alerts > 0 ? 'danger' : stats.open_alerts > 0 ? 'warning' : 'white' },
    { label: 'EDR Detections', value: stats.open_detections, sub: `${stats.total_companies} companies managed`, icon: ShieldAlert, href: '/edr', color: stats.open_detections > 0 ? 'danger' : 'white' },
  ] : [];

  const jobStatusColor = (s: string) => s === 'completed' ? 'text-reap3r-success' : s === 'failed' ? 'text-reap3r-danger' : s === 'running' ? 'text-white' : 'text-reap3r-muted';

  return (
    <>
      <TopBar title="Dashboard" actions={
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2 py-1 bg-reap3r-success/10 border border-reap3r-success/20 rounded-lg">
            <div className="w-1.5 h-1.5 rounded-full bg-reap3r-success animate-pulse" />
            <span className="text-[10px] font-semibold text-reap3r-success">LIVE</span>
          </div>
          <span className="text-[10px] text-reap3r-muted font-mono flex items-center gap-1.5">
            <Clock style={{ width: '10px', height: '10px' }} />{lastRefresh.toLocaleTimeString()}
          </span>
          <button onClick={load} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all" title="Refresh">
            <RefreshCw style={{ width: '13px', height: '13px' }} />
          </button>
        </div>
      } />

      <div className="p-6 space-y-6 animate-fade-in">
        {/* Welcome */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">Welcome back{user?.name ? `, ${user.name}` : ''}</h2>
            <p className="text-xs text-reap3r-muted mt-0.5">{new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</p>
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
            {[...Array(4)].map((_, i) => <div key={i} className="bg-reap3r-card border border-reap3r-border rounded-xl p-5"><Skeleton className="h-9 w-9 rounded-lg mb-4" /><Skeleton className="h-8 w-16 mb-2" /><Skeleton className="h-3 w-24" /></div>)}
          </div>
        ) : (
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            {statCards.map((card) => <StatCard key={card.label} {...card} />)}
          </div>
        )}

        {/* Coverage + OS Distribution */}
        {stats && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card className="!py-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Zap className="text-reap3r-light" style={{ width: '13px', height: '13px' }} />
                  <span className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Agent Coverage</span>
                </div>
                <span className="text-[10px] text-reap3r-muted font-mono">{stats.online_agents} / {stats.total_agents} online</span>
              </div>
              <CoverageBar online={stats.online_agents} total={stats.total_agents} />
              <div className="flex gap-4 mt-3">
                {[
                  { label: 'Online', count: stats.online_agents, color: 'text-reap3r-success' },
                  { label: 'Offline', count: stats.offline_agents, color: 'text-reap3r-muted' },
                  { label: 'Isolated', count: stats.isolated_agents, color: 'text-reap3r-warning' },
                ].map((s) => (
                  <div key={s.label} className="flex items-center gap-1.5">
                    <span className={`text-xs font-bold font-mono ${s.color}`}>{s.count}</span>
                    <span className="text-[10px] text-reap3r-muted uppercase tracking-wider">{s.label}</span>
                  </div>
                ))}
              </div>
            </Card>
            <Card className="!py-4">
              <div className="flex items-center gap-2 mb-3">
                <PieChart className="text-reap3r-light" style={{ width: '13px', height: '13px' }} />
                <span className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">OS Distribution</span>
              </div>
              <OsDistribution data={stats.by_os} />
            </Card>
          </div>
        )}

        {/* Job Summary */}
        {stats && (
          <Card className="!py-4">
            <div className="flex items-center gap-2 mb-3">
              <BarChart3 className="text-reap3r-light" style={{ width: '13px', height: '13px' }} />
              <span className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Job Overview</span>
              <span className="text-[10px] text-reap3r-muted/50 ml-auto font-mono">{stats.total_jobs} total</span>
            </div>
            <MiniBarChart completed={stats.completed_jobs} failed={stats.failed_jobs} running={stats.running_jobs} pending={stats.pending_jobs} />
          </Card>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Recent Agents */}
          <div className="lg:col-span-2 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                <Monitor style={{ width: '11px', height: '11px' }} />Recent Agents
              </h3>
              <Link href="/agents" className="text-[10px] text-reap3r-muted hover:text-white transition-colors flex items-center gap-1">View all <ChevronRight style={{ width: '10px', height: '10px' }} /></Link>
            </div>
            <Card className="!p-0 overflow-hidden">
              {loading ? (
                <div className="p-4 space-y-3">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
              ) : recentAgents.length === 0 ? (
                <div className="py-10 text-center">
                  <p className="text-xs text-reap3r-muted">No agents found.</p>
                  <Link href="/deployment" className="text-[11px] text-white/60 hover:text-white mt-2 inline-block">Deploy your first agent →</Link>
                </div>
              ) : (
                <div className="divide-y divide-reap3r-border/50">
                  {recentAgents.map((agent) => (
                    <Link key={agent.id} href={`/agents/${agent.id}`} className="flex items-center gap-3 px-5 py-3 hover:bg-reap3r-hover/50 transition-colors group">
                      <StatusDot status={agent.status} />
                      <div className="flex-1 min-w-0">
                        <p className="text-[12px] font-semibold text-white truncate group-hover:text-white/90">{agent.hostname}</p>
                        <p className="text-[10px] text-reap3r-muted font-mono truncate">{agent.os} · {agent.last_ip || 'No IP'}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {agent.company_name && <Badge variant="default">{agent.company_name}</Badge>}
                        <span className="text-[10px] text-reap3r-muted font-mono capitalize">{agent.status}</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </Card>
          </div>

          {/* Right column */}
          <div className="space-y-6">
            <div className="space-y-3">
              <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                <Zap style={{ width: '11px', height: '11px' }} />Quick Actions
              </h3>
              <div className="space-y-1.5">
                <QuickAction href="/deployment" icon={Download} label="Deploy Agent" />
                <QuickAction href="/agents" icon={Monitor} label="All Agents" />
                <QuickAction href="/jobs" icon={ListTodo} label="View Jobs" />
                <QuickAction href="/alerting/rules" icon={Bell} label="Alert Rules" />
                <QuickAction href="/edr" icon={ShieldAlert} label="EDR / SOC" />
                <QuickAction href="/settings" icon={Settings} label="Settings" />
              </div>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2">
                  <ListTodo style={{ width: '11px', height: '11px' }} />Recent Jobs
                </h3>
                <Link href="/jobs" className="text-[10px] text-reap3r-muted hover:text-white transition-colors">View all →</Link>
              </div>
              <Card className="!p-0 overflow-hidden">
                {loading ? (
                  <div className="p-3 space-y-2">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-7" />)}</div>
                ) : recentJobs.length === 0 ? (
                  <p className="text-xs text-reap3r-muted p-4 text-center">No jobs yet.</p>
                ) : (
                  <div className="divide-y divide-reap3r-border/50">
                    {recentJobs.map((job) => (
                      <div key={job.id} className="flex items-center gap-3 px-4 py-2.5">
                        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${job.status === 'completed' ? 'bg-reap3r-success' : job.status === 'failed' ? 'bg-reap3r-danger' : job.status === 'running' ? 'bg-white' : 'bg-reap3r-muted'}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] font-medium text-white/80 truncate">{job.type}</p>
                          <p className="text-[10px] text-reap3r-muted font-mono truncate">{job.agent_hostname || 'Unknown'} · {new Date(job.created_at).toLocaleTimeString()}</p>
                        </div>
                        <span className={`text-[10px] font-semibold capitalize font-mono ${jobStatusColor(job.status)}`}>{job.status}</span>
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
              <h3 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em] flex items-center gap-2"><AlertTriangle style={{ width: '11px', height: '11px' }} />Open Alerts</h3>
              <Link href="/alerting" className="text-[10px] text-reap3r-muted hover:text-white transition-colors">View all →</Link>
            </div>
            <div className="space-y-1.5">
              {recentAlerts.map((alert) => (
                <Link key={alert.id} href="/alerting" className="flex items-center gap-4 px-5 py-3 bg-reap3r-card border border-reap3r-border rounded-xl hover:border-reap3r-border-light transition-all duration-150">
                  <AlertTriangle className={alert.severity === 'critical' || alert.severity === 'high' ? 'text-reap3r-danger' : 'text-reap3r-warning'} style={{ width: '13px', height: '13px', flexShrink: 0 }} />
                  <p className="flex-1 text-[12px] font-medium text-white truncate">{alert.title}</p>
                  <Badge variant={alert.severity === 'critical' || alert.severity === 'high' ? 'danger' : 'warning'}>{alert.severity}</Badge>
                  <span className="text-[10px] text-reap3r-muted font-mono shrink-0">{new Date(alert.created_at).toLocaleTimeString()}</span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
