'use client';
import { useEffect, useState } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { ShieldAlert, AlertTriangle, Eye, Bug, Siren, Network, Shield, XCircle, CheckCircle, Plus, X } from 'lucide-react';

type Tab = 'events' | 'detections' | 'incidents';

const severityColor = (s: string) => {
  switch (s) {
    case 'critical': return 'danger';
    case 'high': return 'danger';
    case 'medium': return 'warning';
    case 'low': return 'default';
    default: return 'default';
  }
};

export default function EdrPage() {
  const [tab, setTab] = useState<Tab>('detections');
  const [events, setEvents] = useState<any[]>([]);
  const [detections, setDetections] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  // Detail View
  const [selectedDetection, setSelectedDetection] = useState<any | null>(null);
  const [processTree, setProcessTree] = useState<any[]>([]);
  
  // Response Actions
  const [showResponseModal, setShowResponseModal] = useState(false);
  const [responseAction, setResponseAction] = useState('kill_process');
  const [responseTarget, setResponseTarget] = useState('');
  
  // Create Incident
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState('');
  const [incidentSeverity, setIncidentSeverity] = useState('medium');
  const [incidentDetectionIds, setIncidentDetectionIds] = useState<string[]>([]);

  const loadEvents = () => {
    setLoading(true);
    api.edr.events({ page: String(page), limit: '50' }).then(r => { setEvents(r.data); setTotal(r.total); setLoading(false); }).catch(() => setLoading(false));
  };

  const loadDetections = () => {
    setLoading(true);
    api.edr.detections({ page: String(page), limit: '50' }).then(r => { setDetections(r.data); setTotal(r.total); setLoading(false); }).catch(() => setLoading(false));
  };

  const loadIncidents = () => {
    setLoading(true);
    api.edr.incidents({ page: String(page), limit: '50' }).then(r => { setIncidents(r.data); setTotal(r.total); setLoading(false); }).catch(() => setLoading(false));
  };

  useEffect(() => {
    setPage(1);
    if (tab === 'events') loadEvents();
    else if (tab === 'detections') loadDetections();
    else loadIncidents();
  }, [tab]);

  useEffect(() => {
    if (tab === 'events') loadEvents();
    else if (tab === 'detections') loadDetections();
    else loadIncidents();
  }, [page]);

  const selectDetection = async (detection: any) => {
    setSelectedDetection(detection);
    // Mock process tree (in real impl, call backend /api/edr/detections/:id/process-tree)
    setProcessTree([
      { pid: detection.context?.process_id || 1234, name: detection.context?.process_name || 'suspicious.exe', parent_pid: 1000, user: detection.context?.username || 'SYSTEM' },
      { pid: 1000, name: 'explorer.exe', parent_pid: 4, user: 'user' },
      { pid: 4, name: 'System', parent_pid: 0, user: 'SYSTEM' },
    ]);
  };

  const updateDetectionStatus = async (id: string, status: string) => {
    await api.edr.updateDetection(id, { status });
    loadDetections();
    if (selectedDetection?.id === id) setSelectedDetection(null);
  };

  const createIncident = async () => {
    if (!incidentTitle) return;
    await api.edr.createIncident({ 
      title: incidentTitle, 
      severity: incidentSeverity, 
      status: 'open',
      detection_ids: incidentDetectionIds 
    });
    setShowCreateIncident(false);
    setIncidentTitle('');
    setIncidentDetectionIds([]);
    loadIncidents();
  };

  const executeResponse = async () => {
    if (!responseTarget) return;
    await api.edr.respond({ action: responseAction, target: responseTarget });
    setShowResponseModal(false);
    setResponseTarget('');
    alert(`Response action "${responseAction}" executed successfully.`);
  };

  const tabs: { key: Tab; label: string; icon: any }[] = [
    { key: 'events', label: 'Security Events', icon: Eye },
    { key: 'detections', label: 'Detections', icon: Bug },
    { key: 'incidents', label: 'Incidents', icon: Siren },
  ];

  return (
    <>
      <TopBar 
        title="EDR / SOC" 
        actions={
          <div className="flex gap-2">
            <Button size="sm" onClick={() => setShowResponseModal(true)}><Shield className="w-4 h-4 mr-1" />Response Action</Button>
            <Button size="sm" onClick={() => setShowCreateIncident(true)}><Plus className="w-4 h-4 mr-1" />Create Incident</Button>
          </div>
        }
      />
      <div className="p-6 space-y-4">
        {/* Tabs */}
        <div className="flex gap-1 bg-reap3r-surface p-1 rounded-lg border border-reap3r-border w-fit">
          {tabs.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm transition-colors ${tab === t.key ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text'}`}>
              <t.icon className="w-4 h-4" />{t.label}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="text-reap3r-muted text-sm">Loading...</div>
        ) : tab === 'events' ? (
          events.length === 0 ? (
            <EmptyState icon={<ShieldAlert className="w-8 h-8" />} title="No security events" description="Security events from agents will appear here." />
          ) : (
            <div className="space-y-2">
              {events.map(e => (
                <Card key={e.id} className="flex items-center justify-between !py-3">
                  <div className="flex items-center gap-3">
                    <AlertTriangle className="w-4 h-4 text-reap3r-accent" />
                    <div>
                      <p className="text-sm font-medium text-reap3r-text">{e.event_type}</p>
                      <p className="text-xs text-reap3r-muted">{e.agent_hostname ?? e.agent_id} · {new Date(e.created_at).toLocaleString()}</p>
                    </div>
                  </div>
                  <Badge variant={severityColor(e.severity) as any}>{e.severity}</Badge>
                </Card>
              ))}
            </div>
          )
        ) : tab === 'detections' ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Detections List */}
            <div className="space-y-2">
              {detections.length === 0 ? (
                <EmptyState icon={<Bug className="w-8 h-8" />} title="No detections" description="Detection rules will trigger alerts here." />
              ) : (
                detections.map(d => (
                  <div key={d.id} onClick={() => selectDetection(d)} className="cursor-pointer">
                    <Card className={`hover:bg-reap3r-bg transition-colors ${selectedDetection?.id === d.id ? 'border-reap3r-accent' : ''}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant={severityColor(d.severity) as any}>{d.severity}</Badge>
                            <Badge variant={d.status === 'resolved' ? 'success' : 'warning'}>{d.status}</Badge>
                          </div>
                          <p className="text-sm font-medium text-reap3r-text">{d.rule_name}</p>
                          <p className="text-xs text-reap3r-muted mt-1">{d.agent_hostname ?? d.agent_id} · {new Date(d.created_at).toLocaleString()}</p>
                        </div>
                        <div className="flex gap-1">
                          {d.status !== 'resolved' && (
                            <>
                              <button onClick={(e) => { e.stopPropagation(); updateDetectionStatus(d.id, 'resolved'); }} className="p-1 text-green-500 hover:bg-green-500/10 rounded" title="Mark Resolved">
                                <CheckCircle className="w-4 h-4" />
                              </button>
                              <button onClick={(e) => { e.stopPropagation(); updateDetectionStatus(d.id, 'false_positive'); }} className="p-1 text-gray-500 hover:bg-gray-500/10 rounded" title="False Positive">
                                <XCircle className="w-4 h-4" />
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    </Card>
                  </div>
                ))
              )}
            </div>

            {/* Detection Detail */}
            {selectedDetection && (
              <Card className="h-fit">
                <h3 className="text-sm font-bold text-reap3r-text mb-3">Detection Details</h3>
                <div className="space-y-2 text-xs">
                  <div><span className="text-reap3r-muted">Rule:</span> <span className="text-reap3r-text font-mono">{selectedDetection.rule_name}</span></div>
                  <div><span className="text-reap3r-muted">Agent:</span> <span className="text-reap3r-text">{selectedDetection.agent_hostname || selectedDetection.agent_id}</span></div>
                  <div><span className="text-reap3r-muted">Process:</span> <span className="text-reap3r-text font-mono">{selectedDetection.context?.process_name || 'N/A'}</span></div>
                  <div><span className="text-reap3r-muted">PID:</span> <span className="text-reap3r-text">{selectedDetection.context?.process_id || 'N/A'}</span></div>
                  <div><span className="text-reap3r-muted">User:</span> <span className="text-reap3r-text">{selectedDetection.context?.username || 'N/A'}</span></div>
                </div>

                <hr className="my-3 border-reap3r-border" />

                <h4 className="text-xs font-semibold text-reap3r-text mb-2 flex items-center gap-1"><Network className="w-3 h-3" />Process Tree</h4>
                <div className="space-y-1 pl-3 border-l-2 border-reap3r-border">
                  {processTree.map((proc, idx) => (
                    <div key={idx} className="text-xs">
                      <span className="text-reap3r-text font-mono">{proc.name}</span>
                      <span className="text-reap3r-muted ml-2">(PID: {proc.pid} · {proc.user})</span>
                    </div>
                  ))}
                </div>

                <hr className="my-3 border-reap3r-border" />

                <div className="flex gap-2">
                  <Button size="sm" variant="danger" onClick={() => { setResponseTarget(selectedDetection.context?.process_id?.toString() || ''); setResponseAction('kill_process'); setShowResponseModal(true); }}>
                    <XCircle className="w-3 h-3 mr-1" />Kill Process
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => { setResponseTarget(selectedDetection.agent_hostname || selectedDetection.agent_id); setResponseAction('isolate_host'); setShowResponseModal(true); }}>
                    <Shield className="w-3 h-3 mr-1" />Isolate Host
                  </Button>
                </div>
              </Card>
            )}
          </div>
        ) : (
          incidents.length === 0 ? (
            <EmptyState icon={<Siren className="w-8 h-8" />} title="No incidents" description="Create incidents from detections to track investigations." />
          ) : (
            <div className="space-y-2">
              {incidents.map(i => (
                <Card key={i.id} className="flex items-center justify-between !py-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant={severityColor(i.severity) as any}>{i.severity}</Badge>
                      <Badge variant={i.status === 'closed' ? 'success' : 'warning'}>{i.status}</Badge>
                    </div>
                    <p className="text-sm font-medium text-reap3r-text">{i.title}</p>
                    <p className="text-xs text-reap3r-muted mt-1">Created {new Date(i.created_at).toLocaleString()}</p>
                  </div>
                  {i.status !== 'closed' && (
                    <Button size="sm" variant="secondary" onClick={() => api.edr.updateIncident(i.id, { status: 'closed' }).then(() => loadIncidents())}>
                      <CheckCircle className="w-3 h-3 mr-1" />Close
                    </Button>
                  )}
                </Card>
              ))}
            </div>
          )
        )}

        {/* Pagination */}
        {total > 50 && (
          <div className="flex justify-center gap-2">
            <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <span className="text-sm text-reap3r-muted py-2">Page {page} of {Math.ceil(total / 50)}</span>
            <Button size="sm" variant="secondary" disabled={page >= Math.ceil(total / 50)} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        )}
      </div>

      {/* Response Action Modal */}
      {showResponseModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowResponseModal(false)}>
          <div className="bg-reap3r-surface border border-reap3r-border rounded-lg p-6 max-w-md w-full m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-reap3r-text">Execute Response Action</h3>
              <button onClick={() => setShowResponseModal(false)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-3">
              <select value={responseAction} onChange={e => setResponseAction(e.target.value)} className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text">
                <option value="kill_process">Kill Process</option>
                <option value="isolate_host">Isolate Host</option>
                <option value="quarantine_file">Quarantine File</option>
              </select>
              <input placeholder="Target (PID, hostname, or file path)" value={responseTarget} onChange={e => setResponseTarget(e.target.value)} className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" />
              <div className="flex items-center gap-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <p className="text-xs text-amber-200">This action is irreversible. Confirm before proceeding.</p>
              </div>
              <Button variant="danger" onClick={executeResponse}>Execute Action</Button>
            </div>
          </div>
        </div>
      )}

      {/* Create Incident Modal */}
      {showCreateIncident && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowCreateIncident(false)}>
          <div className="bg-reap3r-surface border border-reap3r-border rounded-lg p-6 max-w-md w-full m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-reap3r-text">Create Incident</h3>
              <button onClick={() => setShowCreateIncident(false)} className="text-reap3r-muted hover:text-reap3r-text"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-3">
              <input placeholder="Incident title" value={incidentTitle} onChange={e => setIncidentTitle(e.target.value)} className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text" />
              <select value={incidentSeverity} onChange={e => setIncidentSeverity(e.target.value)} className="w-full px-3 py-2 bg-reap3r-bg border border-reap3r-border rounded-lg text-sm text-reap3r-text">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
              <div className="space-y-1">
                <p className="text-xs text-reap3r-muted">Link detections (optional):</p>
                <div className="max-h-32 overflow-y-auto space-y-1">
                  {detections.slice(0, 5).map(d => (
                    <label key={d.id} className="flex items-center gap-2 text-xs text-reap3r-text">
                      <input type="checkbox" checked={incidentDetectionIds.includes(d.id)} onChange={e => setIncidentDetectionIds(e.target.checked ? [...incidentDetectionIds, d.id] : incidentDetectionIds.filter(id => id !== d.id))} />
                      {d.rule_name} ({d.agent_hostname || d.agent_id})
                    </label>
                  ))}
                </div>
              </div>
              <Button onClick={createIncident}>Create Incident</Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
