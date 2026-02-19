'use client';
import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useToastHelpers } from '@/lib/toast';
import { exportToCSV } from '@/lib/export';
import { useRealtimeRefresh, WS_ALERT_EVENTS } from '@/hooks/useRealtimeData';
import {
  Bell, BellOff, Check, CheckCheck, Clock, AlertTriangle, X, Filter, FileDown, RefreshCw,
} from 'lucide-react';

const severityVariant = (s: string): 'default' | 'success' | 'warning' | 'danger' | 'accent' => {
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'default';
};

const statusIcon = (s: string) => {
  switch (s) {
    case 'open':         return <Bell className="text-reap3r-danger" style={{ width: '13px', height: '13px' }} />;
    case 'acknowledged': return <Check className="text-reap3r-warning" style={{ width: '13px', height: '13px' }} />;
    case 'snoozed':      return <Clock style={{ width: '13px', height: '13px', color: '#60a5fa' }} />;
    case 'resolved':     return <CheckCheck className="text-reap3r-success" style={{ width: '13px', height: '13px' }} />;
    default:             return <Bell className="text-reap3r-muted" style={{ width: '13px', height: '13px' }} />;
  }
};

type StatusFilter = '' | 'open' | 'acknowledged' | 'snoozed' | 'resolved';
type SeverityFilter = '' | 'critical' | 'high' | 'medium' | 'low';

export default function AlertingPage() {
  const toast = useToastHelpers();
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
  useRealtimeRefresh(WS_ALERT_EVENTS, () => { loadEvents(); loadStats(); }, 1500);

  const handleAck = async (id: string) => {
    try {
      await api.alerts.events.ack(id, actionNote || undefined);
      toast.success('Alert acknowledged');
      setActionNote(''); loadEvents(); loadStats();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const handleResolve = async (id: string) => {
    try {
      await api.alerts.events.resolve(id, actionNote || undefined);
      toast.success('Alert resolved');
      setActionNote(''); loadEvents(); loadStats();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const handleSnooze = async (id: string) => {
    try {
      await api.alerts.events.snooze(id, snoozeMin, actionNote || undefined);
      toast.success(`Alert snoozed for ${snoozeMin} min`);
      setActionNote(''); loadEvents(); loadStats();
    } catch (err: any) { toast.error('Failed', err.message); }
  };

  const handleExport = () => {
    exportToCSV(events, 'alerts', [
      { key: 'title', label: 'Title' }, { key: 'severity', label: 'Severity' },
      { key: 'status', label: 'Status' }, { key: 'rule_name', label: 'Rule' },
      { key: 'entity_type', label: 'Entity' }, { key: 'created_at', label: 'Created' },
    ]);
    toast.info('Exported', `${events.length} alerts exported`);
  };

  const openDetail = async (eventId: string) => {
    const detail = await api.alerts.events.get(eventId);
    setSelectedEvent(detail); setShowDetail(true);
  };

  return (
    <>
      <TopBar
        title="Alerting"
        actions={
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-2 py-1 bg-reap3r-success/10 border border-reap3r-success/20 rounded-lg">
              <div className="w-1.5 h-1.5 rounded-full bg-reap3r-success animate-pulse" />
              <span className="text-[10px] font-semibold text-reap3r-success">LIVE</span>
            </div>
            <Button size="sm" variant="secondary" onClick={handleExport}><FileDown style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export</Button>
            <Link href="/alerting/rules">
              <Button size="sm" variant="secondary">
                <Filter style={{ width: '12px', height: '12px', marginRight: '4px' }} />Manage Rules
              </Button>
            </Link>
            <button onClick={() => { loadEvents(); loadStats(); }} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all"><RefreshCw style={{ width: '13px', height: '13px' }} /></button>
          </div>
        }
      />

      <div className="p-6 space-y-5 animate-fade-in">

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { label: 'Open', value: stats.open_count, color: 'text-reap3r-danger' },
              { label: 'Acknowledged', value: stats.ack_count, color: 'text-reap3r-warning' },
              { label: 'Snoozed', value: stats.snoozed_count, color: 'text-blue-400' },
              { label: 'Resolved (24h)', value: stats.resolved_24h, color: 'text-reap3r-success' },
              { label: 'Critical Open', value: stats.critical_open, color: 'text-reap3r-danger' },
            ].map(s => (
              <Card key={s.label} className="!py-3 text-center">
                <p className={`text-2xl font-black font-mono ${s.color}`}>{s.value}</p>
                <p className="text-[10px] text-reap3r-muted uppercase tracking-[0.1em] mt-1">{s.label}</p>
              </Card>
            ))}
          </div>
        )}

        {/* Filters */}
        <Card className="!py-3 !px-4 flex flex-wrap gap-3 items-center">
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-reap3r-muted uppercase tracking-wider mr-1">Status:</span>
            {(['', 'open', 'acknowledged', 'snoozed', 'resolved'] as StatusFilter[]).map(s => (
              <button key={s || 'all'} onClick={() => { setStatusFilter(s); setPage(1); }}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold uppercase tracking-[0.06em] transition-all ${
                  statusFilter === s ? 'bg-white/8 text-white border border-white/12' : 'text-reap3r-muted hover:text-reap3r-light'
                }`}>
                {s || 'All'}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-reap3r-muted uppercase tracking-wider mr-1">Severity:</span>
            {(['', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(s => (
              <button key={s || 'all'} onClick={() => { setSeverityFilter(s); setPage(1); }}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold uppercase tracking-[0.06em] transition-all ${
                  severityFilter === s ? 'bg-white/8 text-white border border-white/12' : 'text-reap3r-muted hover:text-reap3r-light'
                }`}>
                {s || 'All'}
              </button>
            ))}
          </div>
          <span className="text-[10px] text-reap3r-muted font-mono ml-auto">{total} alerts</span>
        </Card>

        {/* Events */}
        {loading ? (
          <div className="space-y-2">
            {[...Array(5)].map((_, i) => <div key={i} className="h-16 bg-reap3r-card border border-reap3r-border rounded-xl animate-pulse" />)}
          </div>
        ) : events.length === 0 ? (
          <EmptyState icon={<BellOff style={{ width: '28px', height: '28px' }} />} title="No alerts" description="No alert events match your filters." />
        ) : (
          <div className="space-y-1.5">
            {events.map(ev => (
              <div
                key={ev.id}
                className="bg-reap3r-card border border-reap3r-border rounded-xl px-5 py-3.5 hover:border-reap3r-border-light transition-all cursor-pointer"
                onClick={() => openDetail(ev.id)}
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    {statusIcon(ev.status)}
                    <div className="min-w-0 flex-1">
                      <p className="text-[12px] font-semibold text-white truncate">{ev.title}</p>
                      <p className="text-[10px] text-reap3r-muted font-mono mt-0.5">
                        {ev.rule_name && <span className="mr-2">{ev.rule_name}</span>}
                        {ev.entity_type} · {new Date(ev.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge variant={severityVariant(ev.severity)}>{ev.severity}</Badge>
                    <Badge variant={ev.status === 'open' ? 'danger' : ev.status === 'acknowledged' ? 'warning' : ev.status === 'resolved' ? 'success' : 'default'}>
                      {ev.status}
                    </Badge>
                    {ev.status === 'open' && (
                      <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); handleAck(ev.id); }}>
                        <Check style={{ width: '11px', height: '11px' }} />
                      </Button>
                    )}
                    {(ev.status === 'open' || ev.status === 'acknowledged') && (
                      <Button size="sm" onClick={(e) => { e.stopPropagation(); handleResolve(ev.id); }}>
                        <CheckCheck style={{ width: '11px', height: '11px' }} />
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {total > 25 && (
          <div className="flex justify-center gap-2">
            <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</Button>
            <span className="text-xs text-reap3r-muted py-2 font-mono">Page {page} / {Math.ceil(total / 25)}</span>
            <Button size="sm" variant="secondary" disabled={page >= Math.ceil(total / 25)} onClick={() => setPage(p => p + 1)}>Next →</Button>
          </div>
        )}
      </div>

      {/* Detail slide-over */}
      {showDetail && selectedEvent && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowDetail(false)} />
          <div className="relative w-full max-w-lg bg-reap3r-surface border-l border-reap3r-border h-full overflow-y-auto p-6 space-y-5 animate-slide-up shadow-[0_0_80px_rgba(0,0,0,0.9)]">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white tracking-[0.08em] uppercase">Alert Detail</h3>
              <button onClick={() => setShowDetail(false)} className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                <X style={{ width: '14px', height: '14px' }} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-[10px] text-reap3r-muted uppercase tracking-wider mb-1">Title</p>
                <p className="text-sm font-semibold text-white">{selectedEvent.title}</p>
              </div>
              <div className="flex gap-2">
                <Badge variant={severityVariant(selectedEvent.severity)}>{selectedEvent.severity}</Badge>
                <Badge>{selectedEvent.status}</Badge>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                {[
                  ['Entity Type', selectedEvent.entity_type],
                  ['Entity ID', selectedEvent.entity_id?.slice(0, 12) ?? 'N/A'],
                  ['Rule', selectedEvent.rule_name ?? 'N/A'],
                  ['Created', new Date(selectedEvent.created_at).toLocaleString()],
                ].map(([label, value]) => (
                  <div key={label}>
                    <span className="text-reap3r-muted">{label}</span>
                    <p className="text-white font-mono text-[11px] mt-0.5">{value}</p>
                  </div>
                ))}
              </div>

              {selectedEvent.details && Object.keys(selectedEvent.details).length > 0 && (
                <div>
                  <p className="text-[10px] text-reap3r-muted uppercase tracking-wider mb-1.5">Details</p>
                  <pre className="code-block text-[11px] max-h-40">{JSON.stringify(selectedEvent.details, null, 2)}</pre>
                </div>
              )}

              {selectedEvent.acks?.length > 0 && (
                <div>
                  <p className="text-[10px] text-reap3r-muted uppercase tracking-wider mb-2">Timeline</p>
                  <div className="space-y-2">
                    {selectedEvent.acks.map((a: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-xs">
                        <div className="w-1.5 h-1.5 mt-1.5 rounded-full bg-white/40 flex-shrink-0" />
                        <div>
                          <span className="text-white font-medium">{a.action}</span>
                          <span className="text-reap3r-muted"> by {a.user_email}</span>
                          {a.note && <p className="text-reap3r-muted mt-0.5">"{a.note}"</p>}
                          <p className="text-reap3r-muted font-mono text-[10px]">{new Date(a.created_at).toLocaleString()}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedEvent.status !== 'resolved' && (
                <div className="border-t border-reap3r-border pt-4 space-y-3">
                  <textarea
                    value={actionNote}
                    onChange={e => setActionNote(e.target.value)}
                    placeholder="Note (optional)..."
                    rows={2}
                    className="w-full bg-reap3r-bg border border-reap3r-border rounded-lg px-3 py-2 text-sm text-white resize-none
                      placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20"
                  />
                  <div className="flex gap-2 flex-wrap">
                    {selectedEvent.status === 'open' && (
                      <Button size="sm" variant="secondary" onClick={() => { handleAck(selectedEvent.id); setShowDetail(false); }}>
                        <Check style={{ width: '11px', height: '11px', marginRight: '4px' }} />Acknowledge
                      </Button>
                    )}
                    <Button size="sm" onClick={() => { handleResolve(selectedEvent.id); setShowDetail(false); }}>
                      <CheckCheck style={{ width: '11px', height: '11px', marginRight: '4px' }} />Resolve
                    </Button>
                    <div className="flex items-center gap-1">
                      <select
                        value={snoozeMin}
                        onChange={e => setSnoozeMin(Number(e.target.value))}
                        className="bg-reap3r-bg border border-reap3r-border rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none"
                      >
                        {[15, 30, 60, 240, 480, 1440].map(m => (
                          <option key={m} value={m}>{m < 60 ? `${m} min` : `${m / 60}h`}</option>
                        ))}
                      </select>
                      <Button size="sm" variant="secondary" onClick={() => { handleSnooze(selectedEvent.id); setShowDetail(false); }}>
                        <Clock style={{ width: '11px', height: '11px', marginRight: '4px' }} />Snooze
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
