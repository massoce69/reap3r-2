'use client';
import { useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, TabBar, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import { useRealtimeRefresh, WS_EDR_EVENTS } from '@/hooks/useRealtimeData';
import {
  ShieldAlert, AlertTriangle, Eye, Bug, Siren, Network, Crosshair,
  Shield, XCircle, CheckCircle, Plus, FileDown, RefreshCw, Search,
  Activity, Lock, BarChart3, BookOpen, Wifi, WifiOff, Target,
} from 'lucide-react';

type Tab = 'overview' | 'events' | 'detections' | 'incidents' | 'rules' | 'hunting';

const severityVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'default';
};

const statusVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'resolved' || s === 'closed' || s === 'false_positive') return 'success';
  if (s === 'investigating' || s === 'contained') return 'accent';
  if (s === 'open') return 'warning';
  return 'default';
};

// ──────────────────── Stat Card ────────────────────
function StatCard({ label, value, icon, variant = 'default' }: { label: string; value: string | number; icon: React.ReactNode; variant?: 'default' | 'danger' | 'warning' | 'success' }) {
  const colors = {
    default: 'text-white',
    danger: 'text-reap3r-danger',
    warning: 'text-reap3r-warning',
    success: 'text-reap3r-success',
  };
  return (
    <Card className="flex items-center gap-4">
      <div className={`p-2.5 rounded-xl bg-reap3r-surface ${colors[variant]}`}>{icon}</div>
      <div>
        <p className={`text-2xl font-bold ${colors[variant]}`}>{value}</p>
        <p className="text-[10px] text-reap3r-muted uppercase tracking-[0.12em] font-semibold mt-0.5">{label}</p>
      </div>
    </Card>
  );
}

// ──────────────────── MITRE Tag ────────────────────
function MitreTag({ technique, tactic }: { technique?: string | null; tactic?: string | null }) {
  if (!technique && !tactic) return null;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-[9px] font-mono text-purple-400">
      <Target style={{ width: '8px', height: '8px' }} />
      {technique || tactic}
    </span>
  );
}

// ──────────────────── Pagination ────────────────────
function Pagination({ page, total, limit, onPageChange }: { page: number; total: number; limit: number; onPageChange: (p: number) => void }) {
  const pages = Math.ceil(total / limit);
  if (pages <= 1) return null;
  return (
    <div className="flex justify-center gap-2 mt-4">
      <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>← Prev</Button>
      <span className="text-xs text-reap3r-muted py-2 font-mono">Page {page} / {pages}</span>
      <Button size="sm" variant="secondary" disabled={page >= pages} onClick={() => onPageChange(page + 1)}>Next →</Button>
    </div>
  );
}

export default function EdrPage() {
  const toast = useToastHelpers();
  const router = useRouter();
  const [tab, setTab] = useState<Tab>('overview');

  // ── Overview state ──
  const [overview, setOverview] = useState<any>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);

  // ── Lists state ──
  const [events, setEvents] = useState<any[]>([]);
  const [detections, setDetections] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  // ── Detail/selection ──
  const [selectedDetection, setSelectedDetection] = useState<any | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // ── Hunting ──
  const [huntQuery, setHuntQuery] = useState('');
  const [huntResults, setHuntResults] = useState<any[]>([]);
  const [huntTotal, setHuntTotal] = useState(0);
  const [huntLoading, setHuntLoading] = useState(false);
  const [savedQueries, setSavedQueries] = useState<any[]>([]);

  // ── Modals ──
  const [showResponseModal, setShowResponseModal] = useState(false);
  const [responseAction, setResponseAction] = useState('edr_kill_process');
  const [responseTarget, setResponseTarget] = useState('');
  const [responseAgentId, setResponseAgentId] = useState('');
  const [responseReason, setResponseReason] = useState('');
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState('');
  const [incidentSeverity, setIncidentSeverity] = useState('medium');
  const [incidentDetectionIds, setIncidentDetectionIds] = useState<string[]>([]);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [ruleForm, setRuleForm] = useState({ name: '', description: '', severity: 'medium', logic: '{}', mitre_tactic: '', mitre_technique: '' });

  // ──────────────────── Data Loading ────────────────────
  const loadOverview = useCallback(() => {
    setOverviewLoading(true);
    api.edr.overview().then(setOverview).catch(() => {}).finally(() => setOverviewLoading(false));
  }, []);

  const loadData = useCallback(() => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), limit: '50' };
    if (severityFilter) params.severity = severityFilter;
    if (statusFilter) params.status = statusFilter;

    if (tab === 'events') {
      api.edr.events(params).then(r => { setEvents(r.data); setTotal(r.total); }).catch(() => {}).finally(() => setLoading(false));
    } else if (tab === 'detections') {
      api.edr.detections(params).then(r => { setDetections(r.data); setTotal(r.total); }).catch(() => {}).finally(() => setLoading(false));
    } else if (tab === 'incidents') {
      api.edr.incidents(params).then(r => { setIncidents(r.data); setTotal(r.total); }).catch(() => {}).finally(() => setLoading(false));
    } else if (tab === 'rules') {
      api.edr.rules().then(r => { setRules(Array.isArray(r) ? r : []); }).catch(() => {}).finally(() => setLoading(false));
    } else if (tab === 'hunting') {
      api.edr.savedQueries().then(r => setSavedQueries(Array.isArray(r) ? r : [])).catch(() => {});
      setLoading(false);
    } else {
      loadOverview();
      setLoading(false);
    }
  }, [tab, page, severityFilter, statusFilter, loadOverview]);

  useEffect(() => { setPage(1); setSelectedDetection(null); }, [tab]);
  useEffect(() => { loadData(); }, [loadData]);
  useRealtimeRefresh(WS_EDR_EVENTS, () => { if (tab === 'overview') loadOverview(); else loadData(); }, 3000);

  // ──────────────────── Actions ────────────────────
  const updateDetectionStatus = async (id: string, status: string) => {
    try {
      await api.edr.updateDetection(id, { status });
      toast.success(`Detection marked ${status}`);
      loadData();
      if (selectedDetection?.id === id) setSelectedDetection(null);
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const createIncident = async () => {
    if (!incidentTitle) return;
    try {
      await api.edr.createIncident({ title: incidentTitle, severity: incidentSeverity, status: 'open', detection_ids: incidentDetectionIds });
      toast.success('Incident created');
      setShowCreateIncident(false); setIncidentTitle(''); setIncidentDetectionIds([]);
      setTab('incidents');
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const executeResponse = async () => {
    if (!responseAgentId || !responseReason) return;
    try {
      await api.edr.respond({ agent_id: responseAgentId, action: responseAction, payload: { target: responseTarget }, reason: responseReason });
      toast.success('Response action dispatched');
      setShowResponseModal(false); setResponseTarget(''); setResponseReason('');
    } catch (err: any) { toast.error('Response failed', err.message); }
  };

  const runHunt = async () => {
    if (!huntQuery.trim()) return;
    setHuntLoading(true);
    try {
      const r = await api.edr.hunt({ q: huntQuery, limit: '100' });
      setHuntResults(r.data);
      setHuntTotal(r.total);
    } catch (err: any) { toast.error('Hunt failed', err.message); }
    finally { setHuntLoading(false); }
  };

  const saveCurrentQuery = async () => {
    if (!huntQuery.trim()) return;
    try {
      await api.edr.saveHuntQuery({ name: huntQuery.slice(0, 60), query_text: huntQuery });
      toast.success('Query saved');
      api.edr.savedQueries().then(r => setSavedQueries(Array.isArray(r) ? r : [])).catch(() => {});
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const createRule = async () => {
    try {
      const logic = JSON.parse(ruleForm.logic);
      await api.edr.createRule({ ...ruleForm, logic });
      toast.success('Rule created');
      setShowRuleModal(false); setRuleForm({ name: '', description: '', severity: 'medium', logic: '{}', mitre_tactic: '', mitre_technique: '' });
      loadData();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const toggleRule = async (rule: any) => {
    try {
      await api.edr.updateRule(rule.id, { is_active: !rule.is_active });
      toast.success(rule.is_active ? 'Rule disabled' : 'Rule enabled');
      loadData();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const deleteRule = async (id: string) => {
    try {
      await api.edr.deleteRule(id);
      toast.success('Rule deleted');
      loadData();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const handleExport = () => {
    const data = tab === 'events' ? events : tab === 'detections' ? detections : incidents;
    exportToCSV(data, `edr-${tab}`, [
      { key: 'rule_name', label: 'Rule' }, { key: 'severity', label: 'Severity' },
      { key: 'status', label: 'Status' }, { key: 'agent_hostname', label: 'Agent' },
      { key: 'created_at', label: 'Created' },
    ]);
    toast.info('Exported', `${data.length} rows exported`);
  };

  // ──────────────────── Tab Config ────────────────────
  const tabs = [
    { key: 'overview' as Tab, label: 'Overview', icon: <BarChart3 style={{ width: '12px', height: '12px' }} /> },
    { key: 'events' as Tab, label: 'Events', icon: <Eye style={{ width: '12px', height: '12px' }} /> },
    { key: 'detections' as Tab, label: 'Detections', icon: <Bug style={{ width: '12px', height: '12px' }} /> },
    { key: 'incidents' as Tab, label: 'Incidents', icon: <Siren style={{ width: '12px', height: '12px' }} /> },
    { key: 'rules' as Tab, label: 'Rules', icon: <BookOpen style={{ width: '12px', height: '12px' }} /> },
    { key: 'hunting' as Tab, label: 'Hunting', icon: <Crosshair style={{ width: '12px', height: '12px' }} /> },
  ];

  // ──────────────────── Filter bar ────────────────────
  const showFilters = tab === 'events' || tab === 'detections' || tab === 'incidents';
  const FilterBar = showFilters ? (
    <div className="flex gap-2 items-center">
      <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}
        className="px-2 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20">
        <option value="">All Severity</option>
        {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
      </select>
      {(tab === 'detections' || tab === 'incidents') && (
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
          className="px-2 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20">
          <option value="">All Status</option>
          {(tab === 'detections'
            ? ['open', 'acknowledged', 'resolved', 'false_positive', 'monitoring']
            : ['open', 'investigating', 'contained', 'resolved', 'closed']
          ).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      )}
    </div>
  ) : null;

  return (
    <>
      <TopBar
        title="EDR / SOC"
        actions={
          <div className="flex gap-2 items-center">
            <div className="flex items-center gap-1.5 px-2 py-1 bg-reap3r-success/10 border border-reap3r-success/20 rounded-lg">
              <div className="w-1.5 h-1.5 rounded-full bg-reap3r-success animate-pulse" />
              <span className="text-[10px] font-semibold text-reap3r-success">LIVE</span>
            </div>
            {(tab === 'events' || tab === 'detections' || tab === 'incidents') && (
              <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
            )}
            <Button size="sm" variant="secondary" onClick={() => setShowResponseModal(true)}>
              <Shield style={{ width: '12px', height: '12px', marginRight: '4px' }} />Respond
            </Button>
            <Button size="sm" onClick={() => setShowCreateIncident(true)}>
              <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Incident
            </Button>
            <button onClick={loadData} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"><RefreshCw style={{ width: '13px', height: '13px' }} /></button>
          </div>
        }
      />

      <div className="p-6 space-y-4 animate-fade-in">
        <div className="flex items-center justify-between gap-4">
          <TabBar tabs={tabs} active={tab} onChange={setTab} />
          {FilterBar}
        </div>

        {/* ══════════════ OVERVIEW TAB ══════════════ */}
        {tab === 'overview' && (
          overviewLoading ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}
            </div>
          ) : overview ? (
            <div className="space-y-6">
              {/* KPI Row */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard label="Events (24h)" value={overview.events_24h ?? 0} icon={<Activity style={{ width: '18px', height: '18px' }} />} />
                <StatCard label="Open Detections" value={overview.detections_open?.total ?? 0} icon={<Bug style={{ width: '18px', height: '18px' }} />}
                  variant={(overview.detections_open?.critical > 0 || overview.detections_open?.high > 0) ? 'danger' : 'warning'} />
                <StatCard label="Open Incidents" value={overview.incidents_open ?? 0} icon={<Siren style={{ width: '18px', height: '18px' }} />}
                  variant={overview.incidents_open > 0 ? 'danger' : 'success'} />
                <StatCard label="Isolated Devices" value={overview.isolated_devices ?? 0} icon={<Lock style={{ width: '18px', height: '18px' }} />}
                  variant={overview.isolated_devices > 0 ? 'warning' : 'default'} />
              </div>

              {/* Severity breakdown */}
              {overview.detections_open && (
                <Card>
                  <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.1em] mb-3">Detection Severity Breakdown</h3>
                  <div className="grid grid-cols-4 gap-3">
                    {['critical', 'high', 'medium', 'low'].map(sev => (
                      <div key={sev} className="text-center">
                        <p className={`text-xl font-bold ${sev === 'critical' ? 'text-red-500' : sev === 'high' ? 'text-orange-500' : sev === 'medium' ? 'text-yellow-500' : 'text-reap3r-muted'}`}>
                          {overview.detections_open[sev] ?? 0}
                        </p>
                        <p className="text-[10px] text-reap3r-muted uppercase font-semibold mt-0.5">{sev}</p>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Top firing rules */}
              {overview.top_rules_7d?.length > 0 && (
                <Card>
                  <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.1em] mb-3">Top Rules (7 days)</h3>
                  <div className="space-y-2">
                    {overview.top_rules_7d.map((r: any, idx: number) => (
                      <div key={idx} className="flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2">
                          <span className="text-reap3r-muted font-mono w-5">#{idx + 1}</span>
                          <span className="text-white font-semibold">{r.rule_name}</span>
                        </div>
                        <Badge variant="default">{r.count} hits</Badge>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </div>
          ) : (
            <EmptyState icon={<BarChart3 style={{ width: '28px', height: '28px' }} />} title="No EDR data yet" description="Security events will populate the overview once agents start reporting." />
          )
        )}

        {/* ══════════════ EVENTS TAB ══════════════ */}
        {tab === 'events' && (
          loading ? (
            <div className="space-y-2">{[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}</div>
          ) : events.length === 0 ? (
            <EmptyState icon={<ShieldAlert style={{ width: '28px', height: '28px' }} />} title="No security events" description="Security events from agents will appear here." />
          ) : (
            <>
              <Card className="!p-0 overflow-hidden">
                <div className="divide-y divide-reap3r-border/40">
                  {events.map(e => (
                    <div key={e.id} className="flex items-center gap-4 px-5 py-3.5 hover:bg-reap3r-hover/30 transition-colors">
                      <AlertTriangle className="text-reap3r-warning shrink-0" style={{ width: '14px', height: '14px' }} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-[12px] font-semibold text-white">{e.event_type}</p>
                          {e.process_name && <span className="text-[10px] font-mono text-reap3r-muted">{e.process_name}</span>}
                        </div>
                        <p className="text-[10px] text-reap3r-muted font-mono">{e.agent_hostname ?? e.agent_id} · {new Date(e.created_at).toLocaleString()}</p>
                      </div>
                      <Badge variant={severityVariant(e.severity)}>{e.severity}</Badge>
                    </div>
                  ))}
                </div>
              </Card>
              <Pagination page={page} total={total} limit={50} onPageChange={setPage} />
            </>
          )
        )}

        {/* ══════════════ DETECTIONS TAB ══════════════ */}
        {tab === 'detections' && (
          loading ? (
            <div className="space-y-2">{[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}</div>
          ) : (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-2">
                  {detections.length === 0 ? (
                    <EmptyState icon={<Bug style={{ width: '28px', height: '28px' }} />} title="No detections" description="Detection rules will trigger alerts here." />
                  ) : (
                    detections.map(d => (
                      <button
                        key={d.id}
                        onClick={() => setSelectedDetection(d)}
                        className={`w-full text-left bg-reap3r-card border rounded-xl px-5 py-4 hover:border-reap3r-border-light transition-all duration-150 ${
                          selectedDetection?.id === d.id ? 'border-white/20' : 'border-reap3r-border'
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                              <Badge variant={severityVariant(d.severity)}>{d.severity}</Badge>
                              <Badge variant={statusVariant(d.status)}>{d.status}</Badge>
                              <MitreTag technique={d.mitre_technique} tactic={d.mitre_tactic} />
                            </div>
                            <p className="text-[12px] font-semibold text-white">{d.rule_name}</p>
                            <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">{d.agent_hostname ?? d.agent_id} · {new Date(d.created_at).toLocaleString()}</p>
                          </div>
                          {d.status !== 'resolved' && d.status !== 'false_positive' && (
                            <div className="flex gap-1 ml-2 shrink-0">
                              <button onClick={(e) => { e.stopPropagation(); updateDetectionStatus(d.id, 'resolved'); }}
                                className="p-1.5 text-reap3r-success hover:bg-reap3r-success/10 rounded-lg transition-all" title="Resolve">
                                <CheckCircle style={{ width: '14px', height: '14px' }} />
                              </button>
                              <button onClick={(e) => { e.stopPropagation(); updateDetectionStatus(d.id, 'false_positive'); }}
                                className="p-1.5 text-reap3r-muted hover:bg-reap3r-hover rounded-lg transition-all" title="False Positive">
                                <XCircle style={{ width: '14px', height: '14px' }} />
                              </button>
                            </div>
                          )}
                        </div>
                      </button>
                    ))
                  )}
                </div>

                {selectedDetection && (
                  <Card className="h-fit sticky top-20">
                    <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.1em] mb-4">Detection Details</h3>
                    <div className="space-y-2 text-xs">
                      {([
                        ['Rule', selectedDetection.rule_name, true],
                        ['Severity', selectedDetection.severity, false],
                        ['Score', selectedDetection.score, false],
                        ['Agent', selectedDetection.agent_hostname || selectedDetection.agent_id, false],
                        ['Process', selectedDetection.event_process_name || selectedDetection.details?.process_name || 'N/A', true],
                        ['PID', selectedDetection.event_pid || selectedDetection.details?.process_id || 'N/A', false],
                        ['Parent PID', selectedDetection.event_parent_pid || 'N/A', false],
                        ['User', selectedDetection.event_username || selectedDetection.details?.username || 'N/A', false],
                        ['SHA256', selectedDetection.event_sha256 || 'N/A', true],
                        ['MITRE', `${selectedDetection.mitre_tactic || ''} / ${selectedDetection.mitre_technique || ''}`.trim() || 'N/A', false],
                      ] as [string, any, boolean][]).map(([label, value, mono]) => (
                        <div key={label} className="flex items-center justify-between gap-2">
                          <span className="text-reap3r-muted shrink-0">{label}</span>
                          <span className={`text-white ${mono ? 'font-mono' : ''} text-[11px] truncate max-w-[240px]`} title={String(value)}>{String(value)}</span>
                        </div>
                      ))}
                    </div>

                    {/* Cmdline */}
                    {(selectedDetection.event_cmdline || selectedDetection.details?.cmdline) && (
                      <div className="mt-4 pt-3 border-t border-reap3r-border">
                        <h4 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1.5">Command Line</h4>
                        <pre className="text-[10px] text-white font-mono bg-reap3r-surface rounded-lg p-2.5 overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                          {selectedDetection.event_cmdline || selectedDetection.details?.cmdline}
                        </pre>
                      </div>
                    )}

                    {/* Process tree (from enriched data or context) */}
                    <div className="mt-4 pt-3 border-t border-reap3r-border">
                      <h4 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-2 flex items-center gap-1.5">
                        <Network style={{ width: '10px', height: '10px' }} />Process Chain
                      </h4>
                      <div className="space-y-1 pl-3 border-l border-reap3r-border">
                        {selectedDetection.event_parent_pid && (
                          <div className="text-xs">
                            <span className="text-reap3r-muted font-mono">Parent PID {selectedDetection.event_parent_pid}</span>
                          </div>
                        )}
                        <div className="text-xs">
                          <span className="text-white font-mono">{selectedDetection.event_process_name || selectedDetection.details?.process_name || 'unknown'}</span>
                          <span className="text-reap3r-muted ml-2 font-mono">(PID: {selectedDetection.event_pid || selectedDetection.details?.process_id || '?'} · {selectedDetection.event_username || 'SYSTEM'})</span>
                        </div>
                      </div>
                    </div>

                    {/* Response actions */}
                    <div className="mt-4 flex gap-2 flex-wrap">
                      <Button size="sm" variant="danger" onClick={() => {
                        setResponseAgentId(selectedDetection.agent_id);
                        setResponseTarget(String(selectedDetection.event_pid || selectedDetection.details?.process_id || ''));
                        setResponseAction('edr_kill_process'); setShowResponseModal(true);
                      }}>
                        <XCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} />Kill Process
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => {
                        setResponseAgentId(selectedDetection.agent_id);
                        setResponseAction('edr_isolate_machine'); setShowResponseModal(true);
                      }}>
                        <Shield style={{ width: '12px', height: '12px', marginRight: '4px' }} />Isolate Host
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => {
                        setResponseAgentId(selectedDetection.agent_id);
                        setResponseTarget(selectedDetection.event_process_path || selectedDetection.details?.process_path || '');
                        setResponseAction('edr_quarantine_file'); setShowResponseModal(true);
                      }}>
                        <Lock style={{ width: '12px', height: '12px', marginRight: '4px' }} />Quarantine
                      </Button>
                    </div>
                  </Card>
                )}
              </div>
              <Pagination page={page} total={total} limit={50} onPageChange={setPage} />
            </>
          )
        )}

        {/* ══════════════ INCIDENTS TAB ══════════════ */}
        {tab === 'incidents' && (
          loading ? (
            <div className="space-y-2">{[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}</div>
          ) : incidents.length === 0 ? (
            <EmptyState icon={<Siren style={{ width: '28px', height: '28px' }} />} title="No incidents" description="Create incidents from detections to track investigations." />
          ) : (
            <>
              <Card className="!p-0 overflow-hidden">
                <div className="divide-y divide-reap3r-border/40">
                  {incidents.map(i => (
                    <div key={i.id} className="flex items-center gap-4 px-5 py-4 hover:bg-reap3r-hover/30 transition-colors cursor-pointer"
                      onClick={() => router.push(`/edr/incidents/${i.id}`)}>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <Badge variant={severityVariant(i.severity)}>{i.severity}</Badge>
                          <Badge variant={statusVariant(i.status)}>{i.status}</Badge>
                          {i.auto_created && <Badge variant="accent">auto</Badge>}
                          {i.risk_score != null && <span className="text-[10px] font-mono text-reap3r-muted">Risk: {i.risk_score}</span>}
                          {i.mitre_techniques?.map((t: string) => <MitreTag key={t} technique={t} />)}
                        </div>
                        <p className="text-[12px] font-semibold text-white">{i.title}</p>
                        <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">
                          {i.agent_hostname ? `${i.agent_hostname} · ` : ''}{i.detection_count ? `${i.detection_count} detections · ` : ''}
                          {new Date(i.created_at).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        {i.status !== 'closed' && (
                          <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); api.edr.updateIncident(i.id, { status: 'closed' }).then(() => loadData()); }}>
                            <CheckCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} />Close
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
              <Pagination page={page} total={total} limit={50} onPageChange={setPage} />
            </>
          )
        )}

        {/* ══════════════ RULES TAB ══════════════ */}
        {tab === 'rules' && (
          loading ? (
            <div className="space-y-2">{[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}</div>
          ) : (
            <>
              <div className="flex justify-end mb-2">
                <Button size="sm" onClick={() => setShowRuleModal(true)}>
                  <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Create Rule
                </Button>
              </div>
              {rules.length === 0 ? (
                <EmptyState icon={<BookOpen style={{ width: '28px', height: '28px' }} />} title="No detection rules" description="Create custom detection rules or wait for built-in rules to load." />
              ) : (
                <Card className="!p-0 overflow-hidden">
                  <div className="divide-y divide-reap3r-border/40">
                    {rules.map(r => (
                      <div key={r.id} className="flex items-center gap-4 px-5 py-4 hover:bg-reap3r-hover/30 transition-colors">
                        <div className={`w-2 h-2 rounded-full shrink-0 ${r.is_active ? 'bg-reap3r-success' : 'bg-reap3r-muted'}`} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <Badge variant={severityVariant(r.severity)}>{r.severity}</Badge>
                            {r.is_builtin && <Badge variant="accent">built-in</Badge>}
                            <MitreTag technique={r.mitre_technique} tactic={r.mitre_tactic} />
                            {r.tags?.map((t: string) => <span key={t} className="text-[9px] font-mono text-reap3r-muted bg-reap3r-surface px-1 py-0.5 rounded">{t}</span>)}
                          </div>
                          <p className="text-[12px] font-semibold text-white">{r.name}</p>
                          {r.description && <p className="text-[10px] text-reap3r-muted mt-0.5 truncate">{r.description}</p>}
                        </div>
                        <div className="flex gap-1 shrink-0">
                          <Button size="sm" variant="ghost" onClick={() => toggleRule(r)}>
                            {r.is_active ? <WifiOff style={{ width: '12px', height: '12px' }} /> : <Wifi style={{ width: '12px', height: '12px' }} />}
                          </Button>
                          {!r.is_builtin && (
                            <Button size="sm" variant="ghost" onClick={() => deleteRule(r.id)}>
                              <XCircle style={{ width: '12px', height: '12px' }} className="text-reap3r-danger" />
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </>
          )
        )}

        {/* ══════════════ HUNTING TAB ══════════════ */}
        {tab === 'hunting' && (
          <div className="space-y-4">
            {/* Search bar */}
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-reap3r-muted" style={{ width: '14px', height: '14px' }} />
                <input
                  value={huntQuery}
                  onChange={e => setHuntQuery(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && runHunt()}
                  placeholder="Search cmdline, process, SHA256, IP, domain, username..."
                  className="w-full pl-9 pr-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white font-mono focus:outline-none focus:ring-1 focus:ring-white/20"
                />
              </div>
              <Button onClick={runHunt} loading={huntLoading}>
                <Crosshair style={{ width: '12px', height: '12px', marginRight: '4px' }} />Hunt
              </Button>
              <Button variant="secondary" onClick={saveCurrentQuery}>Save</Button>
            </div>

            {/* Saved queries */}
            {savedQueries.length > 0 && (
              <Card>
                <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.1em] mb-3">Saved Queries</h3>
                <div className="flex flex-wrap gap-2">
                  {savedQueries.map(sq => (
                    <button key={sq.id} onClick={() => { setHuntQuery(sq.query_text); }}
                      className="px-2.5 py-1.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white font-mono hover:border-reap3r-border-light transition-all flex items-center gap-1.5">
                      <Search style={{ width: '10px', height: '10px' }} className="text-reap3r-muted" />
                      {sq.name}
                    </button>
                  ))}
                </div>
              </Card>
            )}

            {/* Results */}
            {huntResults.length > 0 && (
              <Card className="!p-0 overflow-hidden">
                <div className="px-5 py-3 border-b border-reap3r-border bg-reap3r-surface/50">
                  <span className="text-[11px] font-semibold text-white">{huntTotal} results</span>
                </div>
                <div className="divide-y divide-reap3r-border/40 max-h-[600px] overflow-y-auto">
                  {huntResults.map(e => (
                    <div key={e.id} className="px-5 py-3 hover:bg-reap3r-hover/30 transition-colors">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge variant={severityVariant(e.severity)}>{e.severity}</Badge>
                        <span className="text-[10px] text-reap3r-muted font-mono">{e.event_type}</span>
                        <span className="text-[10px] text-reap3r-muted">{new Date(e.created_at).toLocaleString()}</span>
                      </div>
                      {e.process_name && <p className="text-[11px] text-white font-mono">{e.process_name} (PID: {e.pid})</p>}
                      {e.cmdline && <pre className="text-[10px] text-reap3r-muted font-mono mt-1 truncate">{e.cmdline}</pre>}
                      {e.dest_ip && <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">→ {e.dest_ip}:{e.dest_port} ({e.dest_domain || 'N/A'})</p>}
                    </div>
                  ))}
                </div>
              </Card>
            )}
            {huntQuery && huntResults.length === 0 && !huntLoading && (
              <EmptyState icon={<Crosshair style={{ width: '28px', height: '28px' }} />} title="No results" description="Try different search terms or broaden your query." />
            )}
          </div>
        )}
      </div>

      {/* ══════════════ Response Modal ══════════════ */}
      <Modal open={showResponseModal} onClose={() => setShowResponseModal(false)} title="Execute Response Action">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Action</label>
            <select value={responseAction} onChange={e => setResponseAction(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20">
              <option value="edr_kill_process">Kill Process</option>
              <option value="edr_isolate_machine">Isolate Host</option>
              <option value="edr_quarantine_file">Quarantine File</option>
              <option value="edr_collect_bundle">Collect Triage Bundle</option>
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Agent ID</label>
            <input placeholder="Agent UUID..." value={responseAgentId} onChange={e => setResponseAgentId(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white font-mono focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Target (PID, path, etc.)</label>
            <input placeholder="Target..." value={responseTarget} onChange={e => setResponseTarget(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Reason</label>
            <input placeholder="Why this action..." value={responseReason} onChange={e => setResponseReason(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="flex items-center gap-2 px-3 py-2.5 bg-reap3r-warning/8 border border-reap3r-warning/20 rounded-lg">
            <AlertTriangle className="text-reap3r-warning shrink-0" style={{ width: '13px', height: '13px' }} />
            <p className="text-[11px] text-reap3r-warning">This action is irreversible. Confirm before proceeding.</p>
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowResponseModal(false)}>Cancel</Button>
            <Button variant="danger" onClick={executeResponse}>Execute</Button>
          </div>
        </div>
      </Modal>

      {/* ══════════════ Create Incident Modal ══════════════ */}
      <Modal open={showCreateIncident} onClose={() => setShowCreateIncident(false)} title="Create Incident">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Title</label>
            <input placeholder="Incident title" value={incidentTitle} onChange={e => setIncidentTitle(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Severity</label>
            <select value={incidentSeverity} onChange={e => setIncidentSeverity(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20">
              {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          {detections.length > 0 && (
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Link Detections</label>
              <div className="max-h-32 overflow-y-auto space-y-1">
                {detections.slice(0, 10).map(d => (
                  <label key={d.id} className="flex items-center gap-2 text-xs text-reap3r-text cursor-pointer">
                    <input type="checkbox" checked={incidentDetectionIds.includes(d.id)}
                      onChange={e => setIncidentDetectionIds(e.target.checked ? [...incidentDetectionIds, d.id] : incidentDetectionIds.filter(id => id !== d.id))} />
                    {d.rule_name} ({d.agent_hostname || d.agent_id?.slice(0, 8)})
                  </label>
                ))}
              </div>
            </div>
          )}
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreateIncident(false)}>Cancel</Button>
            <Button onClick={createIncident}>Create Incident</Button>
          </div>
        </div>
      </Modal>

      {/* ══════════════ Create Rule Modal ══════════════ */}
      <Modal open={showRuleModal} onClose={() => setShowRuleModal(false)} title="Create Detection Rule">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Name</label>
            <input placeholder="Rule name" value={ruleForm.name} onChange={e => setRuleForm(f => ({ ...f, name: e.target.value }))}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Description</label>
            <input placeholder="What does this rule detect?" value={ruleForm.description} onChange={e => setRuleForm(f => ({ ...f, description: e.target.value }))}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Severity</label>
              <select value={ruleForm.severity} onChange={e => setRuleForm(f => ({ ...f, severity: e.target.value }))}
                className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20">
                {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">MITRE Technique</label>
              <input placeholder="T1059.001" value={ruleForm.mitre_technique} onChange={e => setRuleForm(f => ({ ...f, mitre_technique: e.target.value }))}
                className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white font-mono focus:outline-none focus:ring-1 focus:ring-white/20" />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">MITRE Tactic</label>
            <input placeholder="execution, persistence, ..." value={ruleForm.mitre_tactic} onChange={e => setRuleForm(f => ({ ...f, mitre_tactic: e.target.value }))}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Logic (JSON)</label>
            <textarea rows={5} placeholder='{"match":["powershell"],"conditions":{"cmdline":"*encodedcommand*"}}' value={ruleForm.logic}
              onChange={e => setRuleForm(f => ({ ...f, logic: e.target.value }))}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white font-mono focus:outline-none focus:ring-1 focus:ring-white/20 resize-none" />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowRuleModal(false)}>Cancel</Button>
            <Button onClick={createRule}>Create Rule</Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
