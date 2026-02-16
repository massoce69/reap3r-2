'use client';
import { useEffect, useState, useCallback } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Bell, BellOff, Check, CheckCheck, Clock, AlertTriangle,
  Eye, Filter, ChevronDown, X, MessageSquare,
} from 'lucide-react';

const severityVariant = (s: string) => {
  switch (s) {
    case 'critical': return 'danger';
    case 'high': return 'danger';
    case 'medium': return 'warning';
    case 'low': return 'default';
    default: return 'default';
  }
};

const statusIcon = (s: string) => {
  switch (s) {
    case 'open': return <Bell className="w-4 h-4 text-red-400" />;
    case 'acknowledged': return <Check className="w-4 h-4 text-yellow-400" />;
    case 'snoozed': return <Clock className="w-4 h-4 text-blue-400" />;
    case 'resolved': return <CheckCheck className="w-4 h-4 text-green-400" />;
    default: return <Bell className="w-4 h-4" />;
  }
};

type StatusFilter = '' | 'open' | 'acknowledged' | 'snoozed' | 'resolved';
type SeverityFilter = '' | 'critical' | 'high' | 'medium' | 'low' | 'info';

export default function AlertingPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('');
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [actionNote, setActionNote] = useState('');
  const [snoozeMin, setSnoozeMin] = useState(60);
  const [showDetail, setShowDetail] = useState(false);

  const loadEvents = useCallback(() => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), limit: '25' };
    if (statusFilter) params.status = statusFilter;
    if (severityFilter) params.severity = severityFilter;
    api.alerts.events.list(params)
      .then(r => { setEvents(r.data); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, statusFilter, severityFilter]);

  const loadStats = useCallback(() => {
    api.alerts.stats().then(setStats).catch(() => {});
  }, []);

  useEffect(() => { loadEvents(); loadStats(); }, [loadEvents, loadStats]);

  const handleAck = async (id: string) => {
    await api.alerts.events.ack(id, actionNote || undefined);
    setActionNote('');
    loadEvents();
    loadStats();
  };

  const handleResolve = async (id: string) => {
    await api.alerts.events.resolve(id, actionNote || undefined);
    setActionNote('');
    loadEvents();
    loadStats();
  };

  const handleSnooze = async (id: string) => {
    await api.alerts.events.snooze(id, snoozeMin, actionNote || undefined);
    setActionNote('');
    loadEvents();
    loadStats();
  };

  const openDetail = async (eventId: string) => {
    const detail = await api.alerts.events.get(eventId);
    setSelectedEvent(detail);
    setShowDetail(true);
  };

  const statCards = stats ? [
    { label: 'Open', value: stats.open_count, color: 'text-red-400' },
    { label: 'Acknowledged', value: stats.ack_count, color: 'text-yellow-400' },
    { label: 'Snoozed', value: stats.snoozed_count, color: 'text-blue-400' },
    { label: 'Resolved (24h)', value: stats.resolved_24h, color: 'text-green-400' },
    { label: 'Critical Open', value: stats.critical_open, color: 'text-red-500' },
  ] : [];

  return (
    <>
      <TopBar
        title="Alerting"
        actions={
          <Button size="sm" onClick={() => window.location.href = '/alerting/rules'}>
            <Filter className="w-3 h-3 mr-1" /> Manage Rules
          </Button>
        }
      />

      <div className="p-6 space-y-6">
        {/* Stats Row */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {statCards.map(s => (
              <Card key={s.label} className="!py-3 text-center">
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-xs text-reap3r-muted">{s.label}</p>
              </Card>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs text-reap3r-muted">Status:</span>
          {(['', 'open', 'acknowledged', 'snoozed', 'resolved'] as StatusFilter[]).map(s => (
            <button key={s || 'all'} onClick={() => { setStatusFilter(s); setPage(1); }}
              className={`px-3 py-1 rounded-md text-xs transition-colors ${statusFilter === s ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text'}`}>
              {s || 'All'}
            </button>
          ))}
          <span className="text-xs text-reap3r-muted ml-4">Severity:</span>
          {(['', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(s => (
            <button key={s || 'all'} onClick={() => { setSeverityFilter(s); setPage(1); }}
              className={`px-3 py-1 rounded-md text-xs transition-colors ${severityFilter === s ? 'bg-reap3r-accent/10 text-reap3r-accent' : 'text-reap3r-muted hover:text-reap3r-text'}`}>
              {s || 'All'}
            </button>
          ))}
        </div>

        {/* Events list */}
        {loading ? (
          <div className="text-reap3r-muted text-sm">Loading alerts...</div>
        ) : events.length === 0 ? (
          <EmptyState
            icon={<BellOff className="w-8 h-8" />}
            title="No alerts"
            description="No alert events match your filters."
          />
        ) : (
          <div className="space-y-2">
            {events.map(ev => (
              <div key={ev.id} className="bg-reap3r-surface border border-reap3r-border rounded-xl px-5 py-3 hover:border-reap3r-accent/30 transition-colors cursor-pointer"
                onClick={() => openDetail(ev.id)}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    {statusIcon(ev.status)}
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-reap3r-text truncate">{ev.title}</p>
                      <p className="text-xs text-reap3r-muted">
                        {ev.rule_name && <span className="mr-2">{ev.rule_name}</span>}
                        {ev.entity_type}
                        {ev.entity_id ? ` · ${ev.entity_id.slice(0, 8)}...` : ''}
                        {' · '}{new Date(ev.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                    <Badge variant={severityVariant(ev.severity) as any}>{ev.severity}</Badge>
                    <Badge variant={ev.status === 'open' ? 'danger' : ev.status === 'acknowledged' ? 'warning' : ev.status === 'snoozed' ? 'default' : 'success'}>
                      {ev.status}
                    </Badge>
                    {ev.status === 'open' && (
                      <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); handleAck(ev.id); }}>
                        <Check className="w-3 h-3" />
                      </Button>
                    )}
                    {(ev.status === 'open' || ev.status === 'acknowledged') && (
                      <Button size="sm" variant="primary" onClick={(e) => { e.stopPropagation(); handleResolve(ev.id); }}>
                        <CheckCheck className="w-3 h-3" />
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {total > 25 && (
          <div className="flex justify-center gap-2">
            <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <span className="text-sm text-reap3r-muted py-2">Page {page} of {Math.ceil(total / 25)}</span>
            <Button size="sm" variant="secondary" disabled={page >= Math.ceil(total / 25)} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        )}
      </div>

      {/* Detail Slide-over */}
      {showDetail && selectedEvent && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowDetail(false)} />
          <div className="relative w-full max-w-lg bg-reap3r-surface border-l border-reap3r-border h-full overflow-y-auto p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-reap3r-text">Alert Detail</h3>
              <button onClick={() => setShowDetail(false)} className="text-reap3r-muted hover:text-reap3r-text">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <p className="text-xs text-reap3r-muted">Title</p>
                <p className="text-sm text-reap3r-text font-medium">{selectedEvent.title}</p>
              </div>
              <div className="flex gap-2">
                <Badge variant={severityVariant(selectedEvent.severity) as any}>{selectedEvent.severity}</Badge>
                <Badge>{selectedEvent.status}</Badge>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div><span className="text-reap3r-muted">Entity Type:</span> <span className="text-reap3r-text ml-1">{selectedEvent.entity_type}</span></div>
                <div><span className="text-reap3r-muted">Entity ID:</span> <span className="text-reap3r-text ml-1 font-mono">{selectedEvent.entity_id?.slice(0, 12) ?? 'N/A'}</span></div>
                <div><span className="text-reap3r-muted">Rule:</span> <span className="text-reap3r-text ml-1">{selectedEvent.rule_name ?? 'N/A'}</span></div>
                <div><span className="text-reap3r-muted">Created:</span> <span className="text-reap3r-text ml-1">{new Date(selectedEvent.created_at).toLocaleString()}</span></div>
                <div><span className="text-reap3r-muted">Escalation Step:</span> <span className="text-reap3r-text ml-1">{selectedEvent.escalation_step}</span></div>
                {selectedEvent.snoozed_until && (
                  <div><span className="text-reap3r-muted">Snoozed Until:</span> <span className="text-reap3r-text ml-1">{new Date(selectedEvent.snoozed_until).toLocaleString()}</span></div>
                )}
              </div>

              {selectedEvent.details && Object.keys(selectedEvent.details).length > 0 && (
                <div>
                  <p className="text-xs text-reap3r-muted mb-1">Details</p>
                  <pre className="text-xs bg-reap3r-bg p-3 rounded-lg border border-reap3r-border text-reap3r-text overflow-auto max-h-40">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>
              )}

              {/* Timeline */}
              {selectedEvent.acks?.length > 0 && (
                <div>
                  <p className="text-xs text-reap3r-muted mb-2">Timeline</p>
                  <div className="space-y-2">
                    {selectedEvent.acks.map((a: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-xs">
                        <div className="w-2 h-2 mt-1 rounded-full bg-reap3r-accent flex-shrink-0" />
                        <div>
                          <span className="text-reap3r-text font-medium">{a.action}</span>
                          <span className="text-reap3r-muted"> by {a.user_email}</span>
                          {a.note && <p className="text-reap3r-muted mt-0.5">"{a.note}"</p>}
                          <p className="text-reap3r-muted">{new Date(a.created_at).toLocaleString()}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Notifications */}
              {selectedEvent.notifications?.length > 0 && (
                <div>
                  <p className="text-xs text-reap3r-muted mb-2">Notifications</p>
                  <div className="space-y-1">
                    {selectedEvent.notifications.map((n: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <Badge variant={n.status === 'sent' ? 'success' : n.status === 'failed' ? 'danger' : 'default'} >{n.status}</Badge>
                        <span className="text-reap3r-text">{n.channel}</span>
                        <span className="text-reap3r-muted">{n.sent_at ? new Date(n.sent_at).toLocaleString() : ''}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Actions */}
              {selectedEvent.status !== 'resolved' && (
                <div className="border-t border-reap3r-border pt-4 space-y-3">
                  <textarea
                    value={actionNote}
                    onChange={e => setActionNote(e.target.value)}
                    placeholder="Note (optional)..."
                    rows={2}
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-reap3r-text resize-none"
                  />
                  <div className="flex gap-2 flex-wrap">
                    {selectedEvent.status === 'open' && (
                      <Button size="sm" variant="secondary" onClick={() => { handleAck(selectedEvent.id); setShowDetail(false); }}>
                        <Check className="w-3 h-3 mr-1" /> Acknowledge
                      </Button>
                    )}
                    <Button size="sm" onClick={() => { handleResolve(selectedEvent.id); setShowDetail(false); }}>
                      <CheckCheck className="w-3 h-3 mr-1" /> Resolve
                    </Button>
                    <div className="flex items-center gap-1">
                      <select value={snoozeMin} onChange={e => setSnoozeMin(Number(e.target.value))}
                        className="bg-reap3r-bg border border-reap3r-border rounded-lg px-2 py-1.5 text-xs text-reap3r-text">
                        <option value={15}>15 min</option>
                        <option value={30}>30 min</option>
                        <option value={60}>1 hour</option>
                        <option value={240}>4 hours</option>
                        <option value={480}>8 hours</option>
                        <option value={1440}>24 hours</option>
                      </select>
                      <Button size="sm" variant="secondary" onClick={() => { handleSnooze(selectedEvent.id); setShowDetail(false); }}>
                        <Clock className="w-3 h-3 mr-1" /> Snooze
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
