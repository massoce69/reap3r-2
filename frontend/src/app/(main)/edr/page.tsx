'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, TabBar, Modal } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import { useRealtimeRefresh, WS_EDR_EVENTS } from '@/hooks/useRealtimeData';
import {
  ShieldAlert, AlertTriangle, Eye, Bug, Siren, Network,
  Shield, XCircle, CheckCircle, Plus, FileDown, RefreshCw, Search,
} from 'lucide-react';

type Tab = 'events' | 'detections' | 'incidents';

const severityVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'default';
};

export default function EdrPage() {
  const toast = useToastHelpers();
  const [tab, setTab] = useState<Tab>('detections');
  const [events, setEvents] = useState<any[]>([]);
  const [detections, setDetections] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedDetection, setSelectedDetection] = useState<any | null>(null);
  const [processTree, setProcessTree] = useState<any[]>([]);
  const [showResponseModal, setShowResponseModal] = useState(false);
  const [responseAction, setResponseAction] = useState('kill_process');
  const [responseTarget, setResponseTarget] = useState('');
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState('');
  const [incidentSeverity, setIncidentSeverity] = useState('medium');
  const [incidentDetectionIds, setIncidentDetectionIds] = useState<string[]>([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const loadData = () => {
    setLoading(true);
    const params = { page: String(page), limit: '50' };
    if (tab === 'events') {
      api.edr.events(params).then(r => { setEvents(r.data); setTotal(r.total); }).catch(() => {}).finally(() => setLoading(false));
    } else if (tab === 'detections') {
      api.edr.detections(params).then(r => { setDetections(r.data); setTotal(r.total); }).catch(() => {}).finally(() => setLoading(false));
    } else {
      api.edr.incidents(params).then(r => { setIncidents(r.data); setTotal(r.total); }).catch(() => {}).finally(() => setLoading(false));
    }
  };

  useEffect(() => { setPage(1); }, [tab]);
  useEffect(() => { loadData(); }, [tab, page]);
  useRealtimeRefresh(WS_EDR_EVENTS, loadData, 2000);

  const selectDetection = (detection: any) => {
    setSelectedDetection(detection);
    setProcessTree([
      { pid: detection.context?.process_id || 1234, name: detection.context?.process_name || 'suspicious.exe', user: detection.context?.username || 'SYSTEM' },
      { pid: 1000, name: 'explorer.exe', user: 'user' },
      { pid: 4, name: 'System', user: 'SYSTEM' },
    ]);
  };

  const updateDetectionStatus = async (id: string, status: string) => {
    try {
      await api.edr.updateDetection(id, { status });
      toast.success(`Detection ${status}`);
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
    if (!responseTarget) return;
    try {
      await api.edr.respond({ action: responseAction, target: responseTarget });
      toast.success('Response executed');
      setShowResponseModal(false); setResponseTarget('');
    } catch (err: any) { toast.error('Response failed', err.message); }
  };

  const handleExport = () => {
    const data = tab === 'events' ? events : tab === 'detections' ? detections : incidents;
    exportToCSV(data, `edr-${tab}`, tab === 'incidents'
      ? [{ key: 'title', label: 'Title' }, { key: 'severity', label: 'Severity' }, { key: 'status', label: 'Status' }, { key: 'created_at', label: 'Created' }]
      : [{ key: 'rule_name', label: 'Rule' }, { key: 'severity', label: 'Severity' }, { key: 'status', label: 'Status' }, { key: 'agent_hostname', label: 'Agent' }, { key: 'created_at', label: 'Created' }]
    );
    toast.info('Exported', `${data.length} ${tab} exported`);
  };

  const tabs = [
    { key: 'events' as Tab, label: 'Events', icon: <Eye style={{ width: '12px', height: '12px' }} /> },
    { key: 'detections' as Tab, label: 'Detections', icon: <Bug style={{ width: '12px', height: '12px' }} /> },
    { key: 'incidents' as Tab, label: 'Incidents', icon: <Siren style={{ width: '12px', height: '12px' }} /> },
  ];

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
            <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
            <Button size="sm" variant="secondary" onClick={() => setShowResponseModal(true)}>
              <Shield style={{ width: '12px', height: '12px', marginRight: '4px' }} />Response
            </Button>
            <Button size="sm" onClick={() => setShowCreateIncident(true)}>
              <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Incident
            </Button>
            <button onClick={loadData} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"><RefreshCw style={{ width: '13px', height: '13px' }} /></button>
          </div>
        }
      />

      <div className="p-6 space-y-4 animate-fade-in">
        <TabBar tabs={tabs} active={tab} onChange={setTab} />

        {loading ? (
          <div className="space-y-2">
            {[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}
          </div>
        ) : tab === 'events' ? (
          events.length === 0 ? (
            <EmptyState icon={<ShieldAlert style={{ width: '28px', height: '28px' }} />} title="No security events" description="Security events from agents will appear here." />
          ) : (
            <Card className="!p-0 overflow-hidden">
              <div className="divide-y divide-reap3r-border/40">
                {events.map(e => (
                  <div key={e.id} className="flex items-center gap-4 px-5 py-3.5 hover:bg-reap3r-hover/30 transition-colors">
                    <AlertTriangle className="text-reap3r-warning shrink-0" style={{ width: '14px', height: '14px' }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[12px] font-semibold text-white">{e.event_type}</p>
                      <p className="text-[10px] text-reap3r-muted font-mono">{e.agent_hostname ?? e.agent_id} · {new Date(e.created_at).toLocaleString()}</p>
                    </div>
                    <Badge variant={severityVariant(e.severity)}>{e.severity}</Badge>
                  </div>
                ))}
              </div>
            </Card>
          )
        ) : tab === 'detections' ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-2">
              {detections.length === 0 ? (
                <EmptyState icon={<Bug style={{ width: '28px', height: '28px' }} />} title="No detections" description="Detection rules will trigger alerts here." />
              ) : (
                detections.map(d => (
                  <button
                    key={d.id}
                    onClick={() => selectDetection(d)}
                    className={`w-full text-left bg-reap3r-card border rounded-xl px-5 py-4 hover:border-reap3r-border-light transition-all duration-150 ${
                      selectedDetection?.id === d.id ? 'border-white/20' : 'border-reap3r-border'
                    }`}
                  >
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/5 to-transparent rounded-t-xl" />
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1.5">
                          <Badge variant={severityVariant(d.severity)}>{d.severity}</Badge>
                          <Badge variant={d.status === 'resolved' ? 'success' : 'warning'}>{d.status}</Badge>
                        </div>
                        <p className="text-[12px] font-semibold text-white">{d.rule_name}</p>
                        <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">{d.agent_hostname ?? d.agent_id} · {new Date(d.created_at).toLocaleString()}</p>
                      </div>
                      {d.status !== 'resolved' && (
                        <div className="flex gap-1 ml-2 shrink-0">
                          <button
                            onClick={(e) => { e.stopPropagation(); updateDetectionStatus(d.id, 'resolved'); }}
                            className="p-1.5 text-reap3r-success hover:bg-reap3r-success/10 rounded-lg transition-all"
                            title="Mark Resolved"
                          >
                            <CheckCircle style={{ width: '14px', height: '14px' }} />
                          </button>
                          <button
                            onClick={(e) => { e.stopPropagation(); updateDetectionStatus(d.id, 'false_positive'); }}
                            className="p-1.5 text-reap3r-muted hover:bg-reap3r-hover rounded-lg transition-all"
                            title="False Positive"
                          >
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
              <Card className="h-fit">
                <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.1em] mb-4">Detection Details</h3>
                <div className="space-y-2 text-xs">
                  {[
                    ['Rule', selectedDetection.rule_name, true],
                    ['Agent', selectedDetection.agent_hostname || selectedDetection.agent_id, false],
                    ['Process', selectedDetection.context?.process_name || 'N/A', true],
                    ['PID', selectedDetection.context?.process_id || 'N/A', false],
                    ['User', selectedDetection.context?.username || 'N/A', false],
                  ].map(([label, value, mono]) => (
                    <div key={label as string} className="flex items-center justify-between">
                      <span className="text-reap3r-muted">{label}</span>
                      <span className={`text-white ${mono ? 'font-mono' : ''} text-[11px]`}>{value as string}</span>
                    </div>
                  ))}
                </div>

                <div className="mt-4 pt-4 border-t border-reap3r-border">
                  <h4 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-2 flex items-center gap-1.5">
                    <Network style={{ width: '10px', height: '10px' }} />Process Tree
                  </h4>
                  <div className="space-y-1 pl-3 border-l border-reap3r-border">
                    {processTree.map((proc, idx) => (
                      <div key={idx} className="text-xs">
                        <span className="text-white font-mono">{proc.name}</span>
                        <span className="text-reap3r-muted ml-2 font-mono">(PID: {proc.pid} · {proc.user})</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4 flex gap-2">
                  <Button size="sm" variant="danger" onClick={() => {
                    setResponseTarget(selectedDetection.context?.process_id?.toString() || '');
                    setResponseAction('kill_process'); setShowResponseModal(true);
                  }}>
                    <XCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} />Kill Process
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => {
                    setResponseTarget(selectedDetection.agent_hostname || selectedDetection.agent_id);
                    setResponseAction('isolate_host'); setShowResponseModal(true);
                  }}>
                    <Shield style={{ width: '12px', height: '12px', marginRight: '4px' }} />Isolate
                  </Button>
                </div>
              </Card>
            )}
          </div>
        ) : (
          incidents.length === 0 ? (
            <EmptyState icon={<Siren style={{ width: '28px', height: '28px' }} />} title="No incidents" description="Create incidents from detections to track investigations." />
          ) : (
            <Card className="!p-0 overflow-hidden">
              <div className="divide-y divide-reap3r-border/40">
                {incidents.map(i => (
                  <div key={i.id} className="flex items-center gap-4 px-5 py-4 hover:bg-reap3r-hover/30 transition-colors">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant={severityVariant(i.severity)}>{i.severity}</Badge>
                        <Badge variant={i.status === 'closed' ? 'success' : 'warning'}>{i.status}</Badge>
                      </div>
                      <p className="text-[12px] font-semibold text-white">{i.title}</p>
                      <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">Created {new Date(i.created_at).toLocaleString()}</p>
                    </div>
                    {i.status !== 'closed' && (
                      <Button size="sm" variant="secondary" onClick={() => api.edr.updateIncident(i.id, { status: 'closed' }).then(() => loadData())}>
                        <CheckCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} />Close
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          )
        )}

        {total > 50 && (
          <div className="flex justify-center gap-2">
            <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</Button>
            <span className="text-xs text-reap3r-muted py-2 font-mono">Page {page} / {Math.ceil(total / 50)}</span>
            <Button size="sm" variant="secondary" disabled={page >= Math.ceil(total / 50)} onClick={() => setPage(p => p + 1)}>Next →</Button>
          </div>
        )}
      </div>

      {/* Response Modal */}
      <Modal open={showResponseModal} onClose={() => setShowResponseModal(false)} title="Execute Response Action">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Action</label>
            <select value={responseAction} onChange={e => setResponseAction(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20">
              <option value="kill_process">Kill Process</option>
              <option value="isolate_host">Isolate Host</option>
              <option value="quarantine_file">Quarantine File</option>
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Target (PID, hostname, or path)</label>
            <input
              placeholder="Target..."
              value={responseTarget}
              onChange={e => setResponseTarget(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20"
            />
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

      {/* Create Incident Modal */}
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
                {detections.slice(0, 5).map(d => (
                  <label key={d.id} className="flex items-center gap-2 text-xs text-reap3r-text cursor-pointer">
                    <input
                      type="checkbox"
                      checked={incidentDetectionIds.includes(d.id)}
                      onChange={e => setIncidentDetectionIds(e.target.checked ? [...incidentDetectionIds, d.id] : incidentDetectionIds.filter(id => id !== d.id))}
                    />
                    {d.rule_name} ({d.agent_hostname || d.agent_id})
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
    </>
  );
}
