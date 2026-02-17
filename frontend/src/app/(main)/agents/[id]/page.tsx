'use client';
import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, StatusDot, Skeleton, Input } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { formatDate, statusColor } from '@/lib/utils';
import { RolePermissions, Permission, JobType } from '@massvision/shared';
import {
  Monitor, Terminal, Play, RotateCcw, Power, PowerOff,
  Shield, Cpu, HardDrive, Network, Clock, ArrowLeft, Trash2,
  Package, Activity, RefreshCw, ChevronDown, ChevronRight,
  Server, MemoryStick, Wifi, Layers,
} from 'lucide-react';

type Tab = 'overview' | 'inventory' | 'metrics' | 'jobs';

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { user } = useAuth();
  const [agent, setAgent] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>('overview');
  const [scriptOpen, setScriptOpen] = useState(false);
  const [script, setScript] = useState('');
  const [interpreter, setInterpreter] = useState<'bash' | 'powershell' | 'python'>('bash');
  const [submitting, setSubmitting] = useState(false);
  const [recentJobs, setRecentJobs] = useState<any[]>([]);
  const [inventory, setInventory] = useState<any>(null);
  const [metricsData, setMetricsData] = useState<any[]>([]);
  const [metricsPeriod, setMetricsPeriod] = useState(24);

  const userPerms = user ? RolePermissions[user.role as keyof typeof RolePermissions] ?? [] : [];
  const canRunScript = userPerms.includes(Permission.JobRunScript);
  const canReboot = userPerms.includes(Permission.JobReboot);
  const canDelete = userPerms.includes(Permission.AgentDelete);

  const refresh = useCallback(() => {
    if (!id) return;
    Promise.all([
      api.agents.get(id),
      api.jobs.list({ agent_id: id, limit: '10', sort_order: 'desc' }),
    ]).then(([agentData, jobsData]) => {
      setAgent(agentData);
      setRecentJobs(jobsData.data);
      setLoading(false);
    }).catch(() => {
      setLoading(false);
      router.push('/agents');
    });
  }, [id]);

  useEffect(() => { refresh(); }, [refresh]);

  // Load inventory when tab switches
  useEffect(() => {
    if (tab === 'inventory' && id && !inventory) {
      api.agents.inventory(id).then(setInventory).catch(() => {});
    }
  }, [tab, id]);

  // Load metrics when tab switches
  useEffect(() => {
    if (tab === 'metrics' && id) {
      api.agents.metrics(id, metricsPeriod).then(r => setMetricsData(r.data)).catch(() => {});
    }
  }, [tab, id, metricsPeriod]);

  const isOnline = agent?.status === 'online';
  const hasCapability = (cap: string) => {
    const caps = agent?.capabilities;
    if (Array.isArray(caps)) return caps.includes(cap);
    if (caps?.modules) return caps.modules.includes(cap);
    return false;
  };

  const runScript = async () => {
    if (!agent || !script.trim()) return;
    setSubmitting(true);
    try {
      await api.jobs.create({
        agent_id: agent.id,
        type: JobType.RunScript,
        payload: { interpreter, script, timeout_secs: 300, stream_output: false },
        reason: 'Manual script execution from UI',
      });
      setScriptOpen(false);
      setScript('');
      const jobsData = await api.jobs.list({ agent_id: agent.id, limit: '10', sort_order: 'desc' });
      setRecentJobs(jobsData.data);
    } finally {
      setSubmitting(false);
    }
  };

  const sendAction = async (type: JobType, payload: Record<string, unknown>, reason: string) => {
    if (!agent) return;
    await api.jobs.create({ agent_id: agent.id, type, payload, reason });
    const jobsData = await api.jobs.list({ agent_id: agent.id, limit: '10', sort_order: 'desc' });
    setRecentJobs(jobsData.data);
  };

  const collectInventoryNow = async () => {
    if (!id) return;
    try {
      await api.agents.collectInventory(id);
      setTimeout(() => {
        api.agents.inventory(id).then(setInventory).catch(() => {});
      }, 5000);
    } catch {}
  };

  const deleteAgent = async () => {
    if (!agent || !confirm('Are you sure you want to delete this agent?')) return;
    await api.agents.delete(agent.id);
    router.push('/agents');
  };

  if (loading) {
    return (
      <>
        <TopBar title="Agent Details" />
        <div className="p-6 space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </>
    );
  }

  if (!agent) return null;

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: 'overview', label: 'Overview', icon: <Monitor className="w-4 h-4" /> },
    { key: 'inventory', label: 'Inventory', icon: <Package className="w-4 h-4" /> },
    { key: 'metrics', label: 'Metrics', icon: <Activity className="w-4 h-4" /> },
    { key: 'jobs', label: 'Jobs', icon: <Layers className="w-4 h-4" /> },
  ];

  return (
    <>
      <TopBar
        title={agent.hostname}
        actions={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={() => router.push('/agents')}>
              <ArrowLeft className="w-4 h-4" /> Back
            </Button>
            <Button variant="ghost" size="sm" onClick={refresh}>
              <RefreshCw className="w-4 h-4" />
            </Button>
            {canDelete && (
              <Button variant="danger" size="sm" onClick={deleteAgent}>
                <Trash2 className="w-4 h-4" /> Delete
              </Button>
            )}
          </div>
        }
      />
      <div className="p-6 space-y-6">
        {/* Agent Header */}
        <Card>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-reap3r-accent/10 flex items-center justify-center">
                <Monitor className="w-6 h-6 text-reap3r-accent" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-reap3r-text">{agent.hostname}</h3>
                <div className="flex items-center gap-2 mt-1">
                  <StatusDot status={agent.status} />
                  <span className={`text-sm capitalize ${statusColor(agent.status)}`}>{agent.status}</span>
                  {agent.isolated && <Badge variant="danger">ISOLATED</Badge>}
                </div>
              </div>
            </div>
            <div className="flex gap-2 items-center">
              <Badge variant={isOnline ? 'success' : 'default'}>{agent.agent_version}</Badge>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-4">
            <InfoItem icon={<Cpu className="w-4 h-4" />} label="OS" value={`${agent.os} ${agent.os_version ?? ''}`} />
            <InfoItem icon={<HardDrive className="w-4 h-4" />} label="Arch" value={agent.arch} />
            <InfoItem icon={<Network className="w-4 h-4" />} label="IP" value={agent.ip_address ?? agent.last_ip ?? '—'} />
            <InfoItem icon={<Clock className="w-4 h-4" />} label="Last Seen" value={formatDate(agent.last_seen_at)} />
            <InfoItem icon={<Server className="w-4 h-4" />} label="Company" value={agent.company_name ?? '—'} />
          </div>
          {/* Inline metrics summary */}
          {(agent.cpu_percent > 0 || agent.mem_percent > 0) && (
            <div className="flex gap-4 mt-4 border-t border-reap3r-border pt-4">
              {agent.cpu_percent > 0 && <MiniGauge label="CPU" value={agent.cpu_percent} />}
              {agent.mem_percent > 0 && <MiniGauge label="MEM" value={agent.mem_percent} />}
              {agent.disk_percent > 0 && <MiniGauge label="DISK" value={agent.disk_percent} />}
            </div>
          )}
        </Card>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-reap3r-border">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm transition-colors border-b-2 -mb-px ${
                tab === t.key
                  ? 'text-reap3r-accent border-reap3r-accent'
                  : 'text-reap3r-muted border-transparent hover:text-reap3r-text'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {tab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Capabilities */}
            <Card className="lg:col-span-2">
              <h4 className="text-xs font-medium text-reap3r-muted uppercase tracking-wider mb-3">Capabilities</h4>
              <div className="flex flex-wrap gap-1.5">
                {(Array.isArray(agent.capabilities) ? agent.capabilities : agent.capabilities?.modules ?? []).length > 0 ? (
                  (Array.isArray(agent.capabilities) ? agent.capabilities : agent.capabilities?.modules ?? []).map((cap: string) => (
                    <Badge key={cap} variant="accent">{cap}</Badge>
                  ))
                ) : (
                  <span className="text-xs text-reap3r-muted">No capabilities reported</span>
                )}
              </div>
              {/* Folders */}
              {agent.folders?.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-xs font-medium text-reap3r-muted uppercase tracking-wider mb-2">Folders</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {agent.folders.map((f: any) => <Badge key={f.id} variant="default">{f.name}</Badge>)}
                  </div>
                </div>
              )}
            </Card>

            {/* Actions Panel */}
            <Card>
              <h3 className="text-sm font-semibold text-reap3r-text mb-4">Remote Actions</h3>
              {!isOnline && (
                <div className="mb-4 bg-reap3r-warning/5 border border-reap3r-warning/20 rounded-lg px-3 py-2 text-xs text-reap3r-warning">
                  Agent is offline. Actions are disabled.
                </div>
              )}
              <div className="space-y-2">
                <ActionButton icon={<Terminal className="w-4 h-4" />} label="Run Script"
                  disabled={!isOnline || !hasCapability('run_script') || !canRunScript}
                  onClick={() => setScriptOpen(true)} />
                <ActionButton icon={<RotateCcw className="w-4 h-4" />} label="Reboot"
                  disabled={!isOnline || !hasCapability('reboot') || !canReboot}
                  onClick={() => sendAction(JobType.Reboot, { delay_sec: 0, reason: 'Reboot from UI' }, 'Manual reboot')} />
                <ActionButton icon={<PowerOff className="w-4 h-4" />} label="Shutdown"
                  disabled={!isOnline || !hasCapability('shutdown')}
                  onClick={() => sendAction(JobType.Shutdown, { delay_sec: 0, reason: 'Shutdown from UI' }, 'Manual shutdown')} />
                <ActionButton icon={<Package className="w-4 h-4" />} label="Collect Inventory"
                  disabled={!isOnline || !hasCapability('inventory')}
                  onClick={collectInventoryNow} />
                <ActionButton icon={<Shield className="w-4 h-4" />} label="Remote Shell"
                  disabled={!isOnline || !hasCapability('remote_shell')}
                  onClick={() => sendAction(JobType.RemoteShellStart, { shell: agent.os === 'windows' ? 'powershell' : 'bash' }, 'Remote shell from UI')} />
              </div>
            </Card>
          </div>
        )}

        {tab === 'inventory' && (
          <InventoryTab inventory={inventory} onRefresh={collectInventoryNow} />
        )}

        {tab === 'metrics' && (
          <MetricsTab data={metricsData} period={metricsPeriod} onPeriodChange={setMetricsPeriod} />
        )}

        {tab === 'jobs' && (
          <Card>
            <h3 className="text-sm font-semibold text-reap3r-text mb-4">Job History</h3>
            <JobList jobs={recentJobs} />
          </Card>
        )}

        {/* Run Script Dialog */}
        {scriptOpen && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-reap3r-text">Run Script on {agent.hostname}</h3>
              <Button variant="ghost" size="sm" onClick={() => setScriptOpen(false)}>Cancel</Button>
            </div>
            <div className="space-y-3">
              <div className="flex gap-2">
                {(['bash', 'powershell', 'python'] as const).map((i) => (
                  <button key={i} onClick={() => setInterpreter(i)}
                    className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                      interpreter === i
                        ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                        : 'text-reap3r-muted hover:text-reap3r-text bg-reap3r-surface border border-reap3r-border'
                    }`}>{i}</button>
                ))}
              </div>
              <textarea
                className="w-full h-40 px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-reap3r-text font-mono placeholder:text-reap3r-muted/50 focus:outline-none focus:ring-2 focus:ring-reap3r-accent/50 resize-y"
                placeholder={`Enter your ${interpreter} script...`}
                value={script}
                onChange={(e) => setScript(e.target.value)}
              />
              <div className="flex justify-end">
                <Button onClick={runScript} loading={submitting} disabled={!script.trim()}>
                  <Play className="w-4 h-4" /> Execute
                </Button>
              </div>
            </div>
          </Card>
        )}
      </div>
    </>
  );
}

// ── Inventory Tab ──────────────────────────────

function InventoryTab({ inventory, onRefresh }: { inventory: any; onRefresh: () => void }) {
  if (!inventory?.inventory || Object.keys(inventory.inventory).length === 0) {
    return (
      <Card>
        <div className="text-center py-8">
          <Package className="w-10 h-10 mx-auto text-reap3r-muted mb-3" />
          <p className="text-sm text-reap3r-muted mb-4">No inventory data collected yet.</p>
          <Button onClick={onRefresh} size="sm">
            <RefreshCw className="w-4 h-4" /> Collect Now
          </Button>
        </div>
      </Card>
    );
  }

  const inv = inventory.inventory;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* System Info */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <Server className="w-4 h-4 text-reap3r-accent" /> System
        </h3>
        <div className="space-y-2 text-sm">
          <KV label="Hostname" value={inv.hostname} />
          <KV label="OS" value={`${inv.os} ${inv.os_version}`} />
          <KV label="Architecture" value={inv.arch} />
          <KV label="CPU" value={`${inv.cpu_model} (${inv.cpu_cores} cores)`} />
          <KV label="Memory" value={inv.memory_total_bytes ? `${(inv.memory_total_bytes / 1073741824).toFixed(1)} GB` : '—'} />
          <KV label="Processes" value={inv.process_count?.toString() ?? '—'} />
        </div>
      </Card>

      {/* Disks */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-reap3r-accent" /> Storage
        </h3>
        {inv.disks?.length > 0 ? (
          <div className="space-y-3">
            {inv.disks.map((d: any, i: number) => {
              const used = d.total_bytes - d.available_bytes;
              const pct = d.total_bytes > 0 ? (used / d.total_bytes) * 100 : 0;
              return (
                <div key={i}>
                  <div className="flex justify-between text-xs text-reap3r-muted mb-1">
                    <span>{d.mount_point} ({d.fs_type})</span>
                    <span>{(used / 1073741824).toFixed(1)} / {(d.total_bytes / 1073741824).toFixed(1)} GB</span>
                  </div>
                  <div className="h-2 bg-reap3r-border rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${pct > 90 ? 'bg-reap3r-danger' : pct > 70 ? 'bg-reap3r-warning' : 'bg-reap3r-accent'}`}
                      style={{ width: `${Math.min(pct, 100)}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-sm text-reap3r-muted">No disk data.</p>
        )}
      </Card>

      {/* Network Interfaces */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <Wifi className="w-4 h-4 text-reap3r-accent" /> Network
        </h3>
        {inv.network_interfaces?.length > 0 ? (
          <div className="space-y-2">
            {inv.network_interfaces.map((n: any, i: number) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-reap3r-border last:border-0">
                <div>
                  <p className="text-sm text-reap3r-text font-medium">{n.name}</p>
                  <p className="text-xs text-reap3r-muted">{n.mac ?? '—'}</p>
                </div>
                <div className="text-right text-xs text-reap3r-muted">
                  <p>RX: {formatBytes(n.rx_bytes)}</p>
                  <p>TX: {formatBytes(n.tx_bytes)}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-reap3r-muted">No network data.</p>
        )}
      </Card>

      {/* Top Processes */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-reap3r-accent" /> Top Processes
        </h3>
        {inv.top_processes?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-reap3r-muted border-b border-reap3r-border">
                  <th className="text-left py-1.5 pr-3">PID</th>
                  <th className="text-left py-1.5 pr-3">Name</th>
                  <th className="text-right py-1.5 pr-3">CPU%</th>
                  <th className="text-right py-1.5">Memory</th>
                </tr>
              </thead>
              <tbody>
                {inv.top_processes.slice(0, 15).map((p: any, i: number) => (
                  <tr key={i} className="border-b border-reap3r-border/50">
                    <td className="py-1.5 pr-3 text-reap3r-muted">{p.pid}</td>
                    <td className="py-1.5 pr-3 text-reap3r-text font-medium truncate max-w-[150px]">{p.name}</td>
                    <td className="py-1.5 pr-3 text-right">{p.cpu_percent?.toFixed(1)}</td>
                    <td className="py-1.5 text-right text-reap3r-muted">{formatBytes(p.memory_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-reap3r-muted">No process data.</p>
        )}
      </Card>
    </div>
  );
}

// ── Metrics Tab ──────────────────────────────

function MetricsTab({ data, period, onPeriodChange }: { data: any[]; period: number; onPeriodChange: (h: number) => void }) {
  if (data.length === 0) {
    return (
      <Card>
        <div className="text-center py-8">
          <Activity className="w-10 h-10 mx-auto text-reap3r-muted mb-3" />
          <p className="text-sm text-reap3r-muted">No metrics data available yet. Metrics will appear once the agent starts sending telemetry.</p>
        </div>
      </Card>
    );
  }

  const latest = data[data.length - 1];
  const cpuValues = data.map(d => d.cpu_percent).filter(Boolean);
  const memValues = data.map(d => d.memory_used_mb).filter(Boolean);
  const avgCpu = cpuValues.length > 0 ? cpuValues.reduce((a: number, b: number) => a + b, 0) / cpuValues.length : 0;
  const maxCpu = cpuValues.length > 0 ? Math.max(...cpuValues) : 0;
  const avgMem = memValues.length > 0 ? memValues.reduce((a: number, b: number) => a + b, 0) / memValues.length : 0;

  return (
    <div className="space-y-6">
      {/* Period selector */}
      <div className="flex gap-2">
        {[1, 6, 24, 72, 168].map((h) => (
          <button key={h} onClick={() => onPeriodChange(h)}
            className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
              period === h
                ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                : 'text-reap3r-muted bg-reap3r-surface border border-reap3r-border hover:text-reap3r-text'
            }`}>{h < 24 ? `${h}h` : `${h / 24}d`}</button>
        ))}
      </div>

      {/* Stats summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Avg CPU</p>
          <p className="text-xl font-bold text-reap3r-text">{avgCpu.toFixed(1)}%</p>
        </Card>
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Max CPU</p>
          <p className="text-xl font-bold text-reap3r-text">{maxCpu.toFixed(1)}%</p>
        </Card>
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Avg Memory</p>
          <p className="text-xl font-bold text-reap3r-text">{avgMem.toFixed(0)} MB</p>
        </Card>
        <Card className="!p-4">
          <p className="text-xs text-reap3r-muted">Data Points</p>
          <p className="text-xl font-bold text-reap3r-text">{data.length}</p>
        </Card>
      </div>

      {/* ASCII sparkline chart */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3">CPU Usage Over Time</h3>
        <SparklineChart values={cpuValues} max={100} label="%" color="accent" height={80} />
      </Card>

      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3">Memory Usage Over Time</h3>
        <SparklineChart values={memValues} max={latest?.memory_total_mb ?? Math.max(...memValues)} label=" MB" color="accent" height={80} />
      </Card>

      {/* Latest raw data */}
      <Card>
        <h3 className="text-sm font-semibold text-reap3r-text mb-3">Latest Metrics</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
          <KV label="CPU" value={`${latest?.cpu_percent?.toFixed(1) ?? '—'}%`} />
          <KV label="Memory" value={latest?.memory_used_mb ? `${latest.memory_used_mb.toFixed(0)} / ${latest.memory_total_mb?.toFixed(0)} MB` : '—'} />
          <KV label="Processes" value={latest?.process_count?.toString() ?? '—'} />
          <KV label="Load 1m" value={latest?.load_avg_1m?.toFixed(2) ?? '—'} />
        </div>
      </Card>
    </div>
  );
}

// ── Sparkline Chart (pure CSS/div) ───────────

function SparklineChart({ values, max, label, color, height }: {
  values: number[];
  max: number;
  label: string;
  color: string;
  height: number;
}) {
  if (values.length === 0) return <p className="text-sm text-reap3r-muted">No data</p>;

  // Downsample to max 100 bars
  const step = Math.max(1, Math.floor(values.length / 100));
  const sampled = values.filter((_, i) => i % step === 0);

  return (
    <div className="flex items-end gap-px" style={{ height }}>
      {sampled.map((v, i) => {
        const pct = max > 0 ? Math.min((v / max) * 100, 100) : 0;
        return (
          <div key={i} className="flex-1 min-w-[2px] group relative">
            <div
              className={`w-full rounded-t-sm ${pct > 80 ? 'bg-reap3r-danger' : pct > 60 ? 'bg-reap3r-warning' : 'bg-reap3r-accent'}`}
              style={{ height: `${pct}%` }}
            />
            <div className="absolute -top-6 left-1/2 -translate-x-1/2 bg-reap3r-card text-reap3r-text text-[10px] px-1 rounded opacity-0 group-hover:opacity-100 pointer-events-none whitespace-nowrap">
              {v.toFixed(1)}{label}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Job List ─────────────────────────────────

function JobList({ jobs }: { jobs: any[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (jobs.length === 0) {
    return <p className="text-sm text-reap3r-muted py-4 text-center">No jobs for this agent yet.</p>;
  }

  return (
    <div className="divide-y divide-reap3r-border">
      {jobs.map((job) => (
        <div key={job.id}>
          <button
            className="flex items-center gap-3 py-3 w-full text-left hover:bg-reap3r-hover px-2 -mx-2 rounded transition-colors"
            onClick={() => setExpandedId(expandedId === job.id ? null : job.id)}
          >
            {expandedId === job.id ? <ChevronDown className="w-4 h-4 text-reap3r-muted" /> : <ChevronRight className="w-4 h-4 text-reap3r-muted" />}
            <Badge variant={job.status === 'success' || job.status === 'completed' ? 'success' : job.status === 'failed' ? 'danger' : job.status === 'running' ? 'accent' : 'default'}>
              {job.status}
            </Badge>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-reap3r-text">{job.type}</p>
              {job.reason && <p className="text-xs text-reap3r-muted truncate">{job.reason}</p>}
            </div>
            <span className="text-xs text-reap3r-muted">{formatDate(job.created_at)}</span>
          </button>
          {expandedId === job.id && job.result && (
            <div className="px-10 pb-3">
              <pre className="text-xs bg-reap3r-surface border border-reap3r-border rounded-lg p-3 overflow-x-auto text-reap3r-text max-h-48">
                {typeof job.result === 'string' ? job.result : JSON.stringify(job.result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Utility Components ──────────────────────

function InfoItem({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="text-reap3r-muted">{icon}</div>
      <div>
        <p className="text-[10px] text-reap3r-muted uppercase tracking-wider">{label}</p>
        <p className="text-sm text-reap3r-text font-medium">{value}</p>
      </div>
    </div>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-center">
      <span className="text-reap3r-muted">{label}</span>
      <span className="text-reap3r-text font-medium">{value}</span>
    </div>
  );
}

function MiniGauge({ label, value }: { label: string; value: number }) {
  const pct = Math.min(Math.round(value), 100);
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-reap3r-muted w-8">{label}</span>
      <div className="w-20 h-1.5 bg-reap3r-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${pct > 90 ? 'bg-reap3r-danger' : pct > 70 ? 'bg-reap3r-warning' : 'bg-reap3r-accent'}`}
          style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-reap3r-text font-medium">{pct}%</span>
    </div>
  );
}

function ActionButton({ icon, label, disabled, onClick }: {
  icon: React.ReactNode;
  label: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed text-reap3r-text hover:bg-reap3r-hover border border-reap3r-border"
    >
      {icon}
      {label}
    </button>
  );
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}
