'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, StatusDot, Skeleton, PermissionBanner, Input } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { formatDate, statusColor } from '@/lib/utils';
import { RolePermissions, Permission, JobType } from '@massvision/shared';
import {
  Monitor, Terminal, Play, RotateCcw, Power, PowerOff,
  Shield, Cpu, HardDrive, Network, Clock, ArrowLeft, Trash2,
} from 'lucide-react';

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { user } = useAuth();
  const [agent, setAgent] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [scriptOpen, setScriptOpen] = useState(false);
  const [script, setScript] = useState('');
  const [interpreter, setInterpreter] = useState<'bash' | 'powershell' | 'python'>('bash');
  const [submitting, setSubmitting] = useState(false);
  const [recentJobs, setRecentJobs] = useState<any[]>([]);

  const userPerms = user ? RolePermissions[user.role as keyof typeof RolePermissions] ?? [] : [];
  const canRunScript = userPerms.includes(Permission.JobRunScript);
  const canReboot = userPerms.includes(Permission.JobReboot);
  const canDelete = userPerms.includes(Permission.AgentDelete);

  useEffect(() => {
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

  const isOnline = agent?.status === 'online';
  const hasCapability = (cap: string) => agent?.capabilities?.includes(cap) ?? false;

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
      // Refresh jobs
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

  return (
    <>
      <TopBar
        title={agent.hostname}
        actions={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={() => router.push('/agents')}>
              <ArrowLeft className="w-4 h-4" /> Back
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
        {/* Agent Info */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="lg:col-span-2">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-reap3r-accent/10 flex items-center justify-center">
                  <Monitor className="w-6 h-6 text-reap3r-accent" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-reap3r-text">{agent.hostname}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <StatusDot status={agent.status} />
                    <span className={`text-sm capitalize ${statusColor(agent.status)}`}>{agent.status}</span>
                  </div>
                </div>
              </div>
              <Badge variant={isOnline ? 'success' : 'default'}>{agent.agent_version}</Badge>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
              <InfoItem icon={<Cpu className="w-4 h-4" />} label="OS" value={`${agent.os} ${agent.os_version}`} />
              <InfoItem icon={<HardDrive className="w-4 h-4" />} label="Arch" value={agent.arch} />
              <InfoItem icon={<Network className="w-4 h-4" />} label="Last IP" value={agent.last_ip ?? '—'} />
              <InfoItem icon={<Clock className="w-4 h-4" />} label="Last Seen" value={formatDate(agent.last_seen_at)} />
            </div>

            {/* Capabilities */}
            <div className="mt-6">
              <h4 className="text-xs font-medium text-reap3r-muted uppercase tracking-wider mb-2">Capabilities</h4>
              <div className="flex flex-wrap gap-1.5">
                {agent.capabilities?.length > 0 ? (
                  agent.capabilities.map((cap: string) => <Badge key={cap} variant="accent">{cap}</Badge>)
                ) : (
                  <span className="text-xs text-reap3r-muted">No capabilities reported</span>
                )}
              </div>
            </div>
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
              <ActionButton
                icon={<Terminal className="w-4 h-4" />}
                label="Run Script"
                disabled={!isOnline || !hasCapability('run_script') || !canRunScript}
                disabledReason={
                  !canRunScript ? 'Permission denied' :
                  !isOnline ? 'Agent offline' :
                  !hasCapability('run_script') ? 'Capability not available' : undefined
                }
                onClick={() => setScriptOpen(true)}
              />
              <ActionButton
                icon={<RotateCcw className="w-4 h-4" />}
                label="Reboot"
                disabled={!isOnline || !hasCapability('reboot') || !canReboot}
                disabledReason={
                  !canReboot ? 'Permission denied' :
                  !isOnline ? 'Agent offline' :
                  !hasCapability('reboot') ? 'Capability not available' : undefined
                }
                onClick={() => sendAction(JobType.Reboot, { delay_secs: 0, reason: 'Reboot from UI', force: false }, 'Manual reboot')}
              />
              <ActionButton
                icon={<PowerOff className="w-4 h-4" />}
                label="Shutdown"
                disabled={!isOnline || !hasCapability('shutdown')}
                disabledReason={!isOnline ? 'Agent offline' : !hasCapability('shutdown') ? 'Capability not available' : undefined}
                onClick={() => sendAction(JobType.Shutdown, { delay_secs: 0, reason: 'Shutdown from UI', force: false }, 'Manual shutdown')}
              />
              <ActionButton
                icon={<Shield className="w-4 h-4" />}
                label="Remote Shell"
                disabled={!isOnline || !hasCapability('remote_shell')}
                disabledReason={!isOnline ? 'Agent offline' : !hasCapability('remote_shell') ? 'Capability not available' : undefined}
                onClick={() => {/* Phase 3 */}}
              />
              <ActionButton
                icon={<Monitor className="w-4 h-4" />}
                label="Remote Desktop"
                disabled={!isOnline || !hasCapability('remote_desktop')}
                disabledReason={!isOnline ? 'Agent offline' : !hasCapability('remote_desktop') ? 'Capability not available' : undefined}
                onClick={() => {/* Phase 4 */}}
              />
            </div>
          </Card>
        </div>

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
                  <button
                    key={i}
                    onClick={() => setInterpreter(i)}
                    className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                      interpreter === i
                        ? 'bg-reap3r-accent/10 text-reap3r-accent border border-reap3r-accent/20'
                        : 'text-reap3r-muted hover:text-reap3r-text bg-reap3r-surface border border-reap3r-border'
                    }`}
                  >
                    {i}
                  </button>
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

        {/* Recent Jobs */}
        <Card>
          <h3 className="text-sm font-semibold text-reap3r-text mb-4">Recent Jobs</h3>
          <div className="divide-y divide-reap3r-border">
            {recentJobs.length === 0 ? (
              <p className="text-sm text-reap3r-muted py-4 text-center">No jobs for this agent yet.</p>
            ) : (
              recentJobs.map((job) => (
                <div key={job.id} className="flex items-center gap-3 py-3">
                  <Badge variant={job.status === 'success' ? 'success' : job.status === 'failed' ? 'danger' : job.status === 'running' ? 'accent' : 'default'}>
                    {job.status}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-reap3r-text">{job.type}</p>
                    {job.reason && <p className="text-xs text-reap3r-muted truncate">{job.reason}</p>}
                  </div>
                  <span className="text-xs text-reap3r-muted">{formatDate(job.created_at)}</span>
                  {job.result?.exit_code !== undefined && (
                    <Badge variant={job.result.exit_code === 0 ? 'success' : 'danger'}>
                      exit: {job.result.exit_code}
                    </Badge>
                  )}
                </div>
              ))
            )}
          </div>
        </Card>
      </div>
    </>
  );
}

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

function ActionButton({ icon, label, disabled, disabledReason, onClick }: {
  icon: React.ReactNode;
  label: string;
  disabled?: boolean;
  disabledReason?: string;
  onClick: () => void;
}) {
  return (
    <div className="relative group">
      <button
        onClick={onClick}
        disabled={disabled}
        className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors disabled:opacity-40 disabled:cursor-not-allowed text-reap3r-text hover:bg-reap3r-hover border border-reap3r-border"
      >
        {icon}
        {label}
      </button>
      {disabled && disabledReason && (
        <div className="absolute left-0 -bottom-7 text-[10px] text-reap3r-warning opacity-0 group-hover:opacity-100 transition-opacity">
          {disabledReason}
        </div>
      )}
    </div>
  );
}
