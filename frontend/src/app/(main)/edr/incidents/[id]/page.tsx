'use client';
import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, Modal, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { useRealtimeRefresh, WS_EDR_EVENTS } from '@/hooks/useRealtimeData';
import {
  ArrowLeft, Bug, Clock, MessageSquare, ShieldAlert, User,
  Siren, Target, Plus, Activity,
} from 'lucide-react';

const severityVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'default';
};
const statusVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'resolved' || s === 'closed') return 'success';
  if (s === 'investigating' || s === 'contained') return 'accent';
  if (s === 'open') return 'warning';
  return 'default';
};

const entryIcon = (type: string) => {
  switch (type) {
    case 'detection': return <Bug style={{ width: '12px', height: '12px' }} className="text-reap3r-warning" />;
    case 'action': return <ShieldAlert style={{ width: '12px', height: '12px' }} className="text-reap3r-danger" />;
    case 'note': return <MessageSquare style={{ width: '12px', height: '12px' }} className="text-blue-400" />;
    case 'status_change': return <Activity style={{ width: '12px', height: '12px' }} className="text-purple-400" />;
    default: return <Clock style={{ width: '12px', height: '12px' }} className="text-reap3r-muted" />;
  }
};

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const toast = useToastHelpers();
  const id = params.id as string;

  const [incident, setIncident] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Add note modal
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [noteText, setNoteText] = useState('');

  // Status change
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [newStatus, setNewStatus] = useState('investigating');

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      api.edr.incidentDetail(id),
      api.edr.incidentTimeline(id),
    ]).then(([inc, tl]) => {
      setIncident(inc);
      setTimeline(Array.isArray(tl) ? tl : []);
    }).catch(err => {
      toast.error('Failed to load incident', err.message);
    }).finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  useEffect(() => { load(); }, [load]);
  useRealtimeRefresh(WS_EDR_EVENTS, load, 5000);

  const addNote = async () => {
    if (!noteText.trim()) return;
    try {
      await api.edr.addTimelineEntry(id, { entry_type: 'note', summary: noteText });
      toast.success('Note added');
      setShowNoteModal(false); setNoteText('');
      load();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const changeStatus = async () => {
    try {
      await api.edr.updateIncident(id, { status: newStatus });
      // Also add timeline entry
      await api.edr.addTimelineEntry(id, { entry_type: 'status_change', summary: `Status changed to ${newStatus}` });
      toast.success(`Incident marked ${newStatus}`);
      setShowStatusModal(false);
      load();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  if (loading) {
    return (
      <>
        <TopBar title="Incident" />
        <div className="p-6 space-y-4">
          {[...Array(3)].map((_, i) => <div key={i} className="h-20 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}
        </div>
      </>
    );
  }

  if (!incident) {
    return (
      <>
        <TopBar title="Incident" />
        <div className="p-6">
          <EmptyState icon={<Siren style={{ width: '28px', height: '28px' }} />} title="Incident not found" />
          <div className="flex justify-center mt-4">
            <Button variant="secondary" onClick={() => router.push('/edr')}>
              <ArrowLeft style={{ width: '12px', height: '12px', marginRight: '4px' }} />Back
            </Button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <TopBar
        title={`Incident · ${incident.title?.slice(0, 40)}`}
        actions={
          <div className="flex gap-2 items-center">
            <Button size="sm" variant="secondary" onClick={() => router.push('/edr')}>
              <ArrowLeft style={{ width: '12px', height: '12px', marginRight: '4px' }} />Back
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setShowNoteModal(true)}>
              <MessageSquare style={{ width: '12px', height: '12px', marginRight: '4px' }} />Note
            </Button>
            <Button size="sm" onClick={() => setShowStatusModal(true)}>
              <Activity style={{ width: '12px', height: '12px', marginRight: '4px' }} />Status
            </Button>
          </div>
        }
      />

      <div className="p-6 space-y-6 animate-fade-in">
        {/* ── Incident Header Card ── */}
        <Card>
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <Badge variant={severityVariant(incident.severity)}>{incident.severity}</Badge>
                <Badge variant={statusVariant(incident.status)}>{incident.status}</Badge>
                {incident.auto_created && <Badge variant="accent">auto-created</Badge>}
                {incident.risk_score != null && (
                  <span className="text-[10px] font-mono text-reap3r-muted">Risk: {incident.risk_score}</span>
                )}
              </div>
              <h2 className="text-lg font-bold text-white mb-1">{incident.title}</h2>
              <p className="text-[11px] text-reap3r-muted font-mono">
                {incident.agent_hostname ? `Host: ${incident.agent_hostname} · ` : ''}
                Created {new Date(incident.created_at).toLocaleString()}
                {incident.closed_at ? ` · Closed ${new Date(incident.closed_at).toLocaleString()}` : ''}
              </p>
            </div>
          </div>

          {/* MITRE mapping */}
          {(incident.mitre_tactics?.length > 0 || incident.mitre_techniques?.length > 0) && (
            <div className="mt-4 pt-3 border-t border-reap3r-border">
              <h4 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-2 flex items-center gap-1.5">
                <Target style={{ width: '10px', height: '10px' }} />MITRE ATT&CK
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {incident.mitre_tactics?.map((t: string) => (
                  <span key={t} className="px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-[9px] font-mono text-purple-400">{t}</span>
                ))}
                {incident.mitre_techniques?.map((t: string) => (
                  <span key={t} className="px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-[9px] font-mono text-blue-400">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Linked detections */}
          {incident.detections?.length > 0 && (
            <div className="mt-4 pt-3 border-t border-reap3r-border">
              <h4 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-2">
                Linked Detections ({incident.detections.length})
              </h4>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {incident.detections.map((d: any) => (
                  <div key={d.id} className="flex items-center gap-3 text-xs bg-reap3r-surface rounded-lg px-3 py-2">
                    <Bug style={{ width: '12px', height: '12px' }} className="text-reap3r-warning shrink-0" />
                    <div className="flex-1 min-w-0">
                      <span className="text-white font-semibold">{d.rule_name}</span>
                      <span className="text-reap3r-muted ml-2 font-mono">{new Date(d.created_at).toLocaleString()}</span>
                    </div>
                    <Badge variant={severityVariant(d.severity)}>{d.severity}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {incident.notes && (
            <div className="mt-4 pt-3 border-t border-reap3r-border">
              <h4 className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em] mb-1">Notes</h4>
              <p className="text-xs text-reap3r-text whitespace-pre-wrap">{incident.notes}</p>
            </div>
          )}
        </Card>

        {/* ── Timeline ── */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.1em]">Investigation Timeline</h3>
            <Button size="sm" variant="ghost" onClick={() => setShowNoteModal(true)}>
              <Plus style={{ width: '10px', height: '10px', marginRight: '4px' }} />Add Entry
            </Button>
          </div>

          {timeline.length === 0 ? (
            <p className="text-xs text-reap3r-muted text-center py-6">No timeline entries yet. Add a note to start the investigation log.</p>
          ) : (
            <div className="relative">
              <div className="absolute left-[15px] top-0 bottom-0 w-px bg-reap3r-border" />
              <div className="space-y-4">
                {timeline.map(entry => (
                  <div key={entry.id} className="flex gap-3 relative">
                    <div className="w-8 h-8 rounded-full bg-reap3r-surface border border-reap3r-border flex items-center justify-center shrink-0 z-10">
                      {entryIcon(entry.entry_type)}
                    </div>
                    <div className="flex-1 min-w-0 pt-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-[10px] font-semibold text-white uppercase">{entry.entry_type}</span>
                        <span className="text-[10px] text-reap3r-muted font-mono">{new Date(entry.ts).toLocaleString()}</span>
                        {entry.actor_name && (
                          <span className="text-[10px] text-reap3r-muted flex items-center gap-0.5">
                            <User style={{ width: '9px', height: '9px' }} />{entry.actor_name}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-reap3r-text">{entry.summary}</p>
                      {entry.metadata && Object.keys(entry.metadata).length > 0 && (
                        <pre className="text-[10px] text-reap3r-muted font-mono bg-reap3r-surface rounded-lg p-2 mt-1.5 overflow-x-auto">
                          {JSON.stringify(entry.metadata, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* ── Note Modal ── */}
      <Modal open={showNoteModal} onClose={() => setShowNoteModal(false)} title="Add Investigation Note">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">Note</label>
            <textarea rows={4} placeholder="What did you find?" value={noteText} onChange={e => setNoteText(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20 resize-none" />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowNoteModal(false)}>Cancel</Button>
            <Button onClick={addNote}>Add Note</Button>
          </div>
        </div>
      </Modal>

      {/* ── Status Modal ── */}
      <Modal open={showStatusModal} onClose={() => setShowStatusModal(false)} title="Change Incident Status">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.14em]">New Status</label>
            <select value={newStatus} onChange={e => setNewStatus(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-white/20">
              {['open', 'investigating', 'contained', 'resolved', 'closed'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowStatusModal(false)}>Cancel</Button>
            <Button onClick={changeStatus}>Update Status</Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
