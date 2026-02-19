'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Skeleton, Badge, StatusDot } from '@/components/ui';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { useRealtimeClient } from '@/lib/ws';
import {
  Monitor, ListTodo, CheckCircle, AlertTriangle, Activity, Clock,
  Shield, Lock, Cpu, Bell, Eye, ShieldAlert,
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

  useEffect(() => {
    if (!ws) return;
    const handleUpdate = () => {
      const timer = setTimeout(loadData, 2000);
      return () => clearTimeout(timer);
    };
    const unsub1 = ws.on('agent_online', handleUpdate);
    const unsub2 = ws.on('agent_offline', handleUpdate);
    const unsub3 = ws.on('job_update', handleUpdate);
    const unsub4 = ws.on('alert_event', handleUpdate);
    return () => { unsub1(); unsub2(); unsub3(); unsub4(); };
  }, [ws, loadData]);

  const stats      = data?.agentStats;
  const jStats     = data?.jobStats;
  const aStats     = data?.alertStats;

  const agentsOnline   = stats?.online   ?? data?.agents.data.filter((a) => a.status === 'online').length  ?? 0;
  const agentsTotal    = stats?.total    ?? data?.agents.total  ?? 0;
  const agentsOffline  = stats?.offline  ?? 0;
  const agentsIsolated = stats?.isolated ?? 0;

  const jobsRunning = jStats?.running ?? data?.jobs.data.filter(j => j.status === 'running').length ?? 0;
  const jobsSuccess = jStats?.success ?? data?.jobs.data.filter((j) => j.status === 'success').length ?? 0;
  const jobsFailed  = jStats?.failed  ?? data?.jobs.data.filter((j) => j.status === 'failed').length  ?? 0;

  const alertsOpen        = aStats?.open     ?? 0;
  const alertsCritical    = aStats?.critical ?? 0;
  const edrOpenDetections = data?.edrDetections?.total ?? 0;
  const edrOpenIncidents  = data?.edrIncidents?.total  ?? 0;

  return (
    <>
      <TopBar title="Dashboard" />
      <div className="p-6 space-y-5">

        {/* ── Stat Row ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          <StatCard icon={<Monitor />}       label="Online"    value={loading ? '—' : `${agentsOnline}`}      sub={`/${agentsTotal}`} color="accent"  href="/agents" />
          <StatCard icon={<Activity />}      label="Offline"   value={loading ? '—' : `${agentsOffline}`}                             color="warning" href="/agents" />
          <StatCard icon={<Lock />}          label="Isolated"  value={loading ? '—' : `${agentsIsolated}`}                            color="danger"  href="/agents" />
          <StatCard icon={<Cpu />}           label="Running"   value={loading ? '—' : `${jobsRunning}`}       sub="jobs"              color="accent"  href="/jobs" />
          <StatCard icon={<CheckCircle />}   label="Success"   value={loading ? '—' : `${jobsSuccess}`}                               color="success" href="/jobs" />
          <StatCard icon={<AlertTriangle />} label="Failed"    value={loading ? '—' : `${jobsFailed}`}                                color="danger"  href="/jobs" />
          <StatCard icon={<Bell />}          label="Alerts"    value={loading ? '—' : `${alertsOpen}`}        sub="open"              color="warning" href="/alerting" />
          <StatCard icon={<ShieldAlert />}   label="EDR"       value={loading ? '—' : `${edrOpenDetections}`} sub="det."              color="danger"  href="/edr" />
        </div>

        {/* Coverage bar */}
        {!loading && agentsTotal > 0 && (
          <div className="flex items-center gap-3 px-1">
            <span className="text-[9px] text-reap3r-muted uppercase tracking-[0.18em] font-mono shrink-0 w-24">Coverage</span>
            <div className="flex-1 h-[3px] bg-reap3r-border rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.round((agentsOnline / agentsTotal) * 100)}%`,
                  background: 'linear-gradient(90deg, #00d4ff, #00e5a0)',
                  boxShadow: '0 0 6px rgba(0,212,255,0.5)',
                  transition: 'width 0.8s cubic-bezier(0.4,0,0.2,1)',
                }}
              />
            </div>
            <span className="text-[10px] text-reap3r-accent font-mono font-bold shrink-0 w-10 text-right">
              {Math.round((agentsOnline / agentsTotal) * 100)}%
            </span>
          </div>
        )}

        {/* ── Main 3-col ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

          {/* Agents */}
          <Card className="!p-0 overflow-hidden">
            <SectionHeader icon={<Monitor className="w-3.5 h-3.5" />} title="Agents" href="/agents" color="accent" />
            <div className="px-4 pb-4">
              {loading ? (
                <div className="space-y-2 pt-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
              ) : data?.agents.data.length === 0 ? (
                <p className="text-xs text-reap3r-muted py-6 text-center">No agents enrolled yet.</p>
              ) : (
                <div className="divide-y divide-reap3r-border/40">
                  {data?.agents.data.map((agent) => (
                    <Link
                      key={agent.id}
                      href={`/agents/${agent.id}`}
                      className="flex items-center gap-3 py-2.5 hover:bg-reap3r-hover/50 px-2 -mx-2 rounded-lg transition-colors group"
                    >
                      <StatusDot status={agent.status} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold text-reap3r-text truncate group-hover:text-reap3r-accent transition-colors">
                          {agent.hostname}
                        </p>
                        <p className="text-[10px] text-reap3r-muted font-mono">{agent.os} · {agent.arch}</p>
                      </div>
                      <div className="text-right shrink-0">
                        {agent.cpu_percent > 0 && (
                          <p className="text-[10px] text-reap3r-muted font-mono">CPU {Math.round(agent.cpu_percent)}%</p>
                        )}
                        <span className="text-[10px] text-reap3r-muted/50">{formatDate(agent.last_seen_at)}</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </Card>

          {/* Jobs */}
          <Card className="!p-0 overflow-hidden">
            <SectionHeader icon={<ListTodo className="w-3.5 h-3.5" />} title="Recent Jobs" href="/jobs" color="secondary" />
            <div className="px-4 pb-4">
              {loading ? (
                <div className="space-y-2 pt-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
              ) : data?.jobs.data.length === 0 ? (
                <p className="text-xs text-reap3r-muted py-6 text-center">No jobs yet.</p>
              ) : (
                <div className="divide-y divide-reap3r-border/40">
                  {data?.jobs.data.map((job) => (
                    <div key={job.id} className="flex items-center gap-3 py-2.5">
                      <div className="w-6 h-6 rounded-md bg-reap3r-hover border border-reap3r-border flex items-center justify-center shrink-0">
                        <Clock className="w-3 h-3 text-reap3r-muted" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-reap3r-text truncate">{job.type}</p>
                        <p className="text-[10px] text-reap3r-muted/60 font-mono">{formatDate(job.created_at)}</p>
                      </div>
                      <Badge variant={
                        job.status === 'success' ? 'success'
                        : job.status === 'failed' ? 'danger'
                        : job.status === 'running' ? 'accent'
                        : 'default'
                      }>
                        {job.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>

          {/* Security */}
          <div className="space-y-4">
            {/* Alerts */}
            <Card className="!p-0 overflow-hidden">
              <SectionHeader icon={<Bell className="w-3.5 h-3.5" />} title="Open Alerts" href="/alerting" color="warning" />
              <div className="px-4 pb-4 pt-1">
                {loading ? <Skeleton className="h-10 w-full" /> : alertsOpen === 0 ? (
                  <div className="flex items-center gap-2 text-xs text-reap3r-success py-1">
                    <CheckCircle className="w-3.5 h-3.5" /> All clear
                  </div>
                ) : (
                  <div className="space-y-2">
                    <MetricRow label="Open alerts" value={alertsOpen} variant="warning" />
                    {alertsCritical > 0 && <MetricRow label="Critical" value={alertsCritical} variant="danger" />}
                  </div>
                )}
              </div>
            </Card>

            {/* EDR */}
            <Card className="!p-0 overflow-hidden">
              <SectionHeader icon={<ShieldAlert className="w-3.5 h-3.5" />} title="EDR Status" href="/edr" color="danger" />
              <div className="px-4 pb-4 pt-1">
                {loading ? <Skeleton className="h-10 w-full" /> : edrOpenDetections === 0 && edrOpenIncidents === 0 ? (
                  <div className="flex items-center gap-2 text-xs text-reap3r-success py-1">
                    <Shield className="w-3.5 h-3.5" /> No open threats
                  </div>
                ) : (
                  <div className="space-y-2">
                    <MetricRow label="Detections" value={edrOpenDetections} variant="warning" />
                    <MetricRow label="Incidents"  value={edrOpenIncidents}  variant="danger" />
                  </div>
                )}
              </div>
            </Card>

            {/* Health */}
            <Card className="!p-0 overflow-hidden">
              <SectionHeader icon={<Eye className="w-3.5 h-3.5" />} title="Platform Health" color="accent" />
              <div className="px-4 pb-4 pt-1 space-y-2.5">
                <HealthRow label="Agent coverage"  value={agentsTotal > 0 ? `${Math.round((agentsOnline / agentsTotal) * 100)}%` : '—'} loading={loading} />
                <HealthRow label="Job success"     value={(jobsSuccess + jobsFailed) > 0 ? `${Math.round((jobsSuccess / (jobsSuccess + jobsFailed)) * 100)}%` : '—'} loading={loading} />
                <HealthRow label="Total agents"    value={loading ? '—' : `${agentsTotal}`} loading={loading} />
              </div>
            </Card>
          </div>
        </div>
      </div>
    </>
  );
}

/* ── Sub-components ───────────────────────────────────── */

const COLORS: Record<string, { icon: string; bar: string }> = {
  accent:    { icon: 'text-reap3r-accent   bg-reap3r-accent/10   border-reap3r-accent/20',   bar: '#00d4ff' },
  success:   { icon: 'text-reap3r-success  bg-reap3r-success/10  border-reap3r-success/20',  bar: '#00e5a0' },
  danger:    { icon: 'text-reap3r-danger   bg-reap3r-danger/10   border-reap3r-danger/20',   bar: '#ff4757' },
  warning:   { icon: 'text-reap3r-warning  bg-reap3r-warning/10  border-reap3r-warning/20',  bar: '#f5a623' },
  secondary: { icon: 'text-reap3r-secondary bg-reap3r-secondary/10 border-reap3r-secondary/20', bar: '#7c3aed' },
};

function StatCard({
  icon, label, value, sub, color, href,
}: {
  icon: React.ReactNode; label: string; value: string; sub?: string; color: string; href?: string;
}) {
  const c = COLORS[color] ?? COLORS.accent;
  const inner = (
    <div
      className="relative bg-reap3r-card border border-reap3r-border rounded-xl p-3.5 overflow-hidden transition-all duration-200 hover:border-reap3r-border-light h-full"
      style={{ boxShadow: '0 4px 16px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.02)' }}
    >
      <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${c.bar}50, transparent)` }} />
      <div className="absolute inset-0 bg-gradient-to-br from-white/[0.012] to-transparent pointer-events-none" />
      <div className={`w-7 h-7 rounded-lg border flex items-center justify-center mb-2.5 ${c.icon}`}>
        <span style={{ width: '13px', height: '13px', display: 'flex' }}>{icon}</span>
      </div>
      <div className="flex items-baseline gap-1">
        <p className="text-xl font-bold text-reap3r-text font-mono leading-none">{value}</p>
        {sub && <span className="text-[10px] text-reap3r-muted font-mono">{sub}</span>}
      </div>
      <p className="text-[9px] text-reap3r-muted uppercase tracking-[0.12em] mt-1 font-semibold">{label}</p>
    </div>
  );
  return href ? <Link href={href} className="block">{inner}</Link> : <div>{inner}</div>;
}

function SectionHeader({
  icon, title, href, color = 'accent',
}: {
  icon: React.ReactNode; title: string; href?: string; color?: string;
}) {
  const c = COLORS[color] ?? COLORS.accent;
  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-reap3r-border/50">
      <div className="flex items-center gap-2">
        <span className={`w-5 h-5 rounded border flex items-center justify-center shrink-0 ${c.icon}`}>{icon}</span>
        <span className="text-[10px] font-bold text-reap3r-text uppercase tracking-[0.15em]">{title}</span>
      </div>
      {href && (
        <Link href={href} className="text-[10px] text-reap3r-muted hover:text-reap3r-accent transition-colors font-mono">
          All →
        </Link>
      )}
    </div>
  );
}

function MetricRow({ label, value, variant }: { label: string; value: number; variant: any }) {
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-xs text-reap3r-light">{label}</span>
      <Badge variant={variant}>{value}</Badge>
    </div>
  );
}

function HealthRow({ label, value, loading }: { label: string; value: string; loading: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[11px] text-reap3r-muted">{label}</span>
      {loading ? <Skeleton className="h-3 w-10" /> : <span className="text-[11px] font-bold text-reap3r-text font-mono">{value}</span>}
    </div>
  );
}
