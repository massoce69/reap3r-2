'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal, TabBar } from '@/components/ui';
import { api } from '@/lib/api';
import { BrowserDeployTab } from '@/components/deploy/BrowserDeployTab';
import {
  Download, Copy, Key, Terminal, Monitor as MonitorIcon, Check,
  Plus, Trash2, ArrowRight, Upload, Play, RotateCcw, XCircle,
  FileSpreadsheet, Server, Shield, Clock, CheckCircle2, AlertTriangle,
  Activity, RefreshCw, Monitor
} from 'lucide-react';

// ═══════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════
interface DeployBatch {
  batch_id: string; filename: string; mode: string; status: string;
  total_items: number; valid_count: number; invalid_count: number;
  success_count: number; failed_count: number; skipped_count: number;
  created_at: string; started_at: string | null; finished_at: string | null;
  zabbix_url: string | null; server_url: string; error: string | null;
}

interface DeployItem {
  id: string; row_number: number; zabbix_host: string; dat: string;
  status: string; validation_error: string | null; attempt_count: number;
  last_error: string | null; callback_received: boolean; callback_status: string | null;
  callback_exit: number | null; started_at: string | null; finished_at: string | null;
}

// ═══════════════════════════════════════════
// STATUS HELPERS
// ═══════════════════════════════════════════
const batchStatusBadge = (s: string) => {
  const map: Record<string, { variant: 'default' | 'success' | 'warning' | 'danger' | 'accent'; label: string }> = {
    created: { variant: 'default', label: 'Created' },
    validating: { variant: 'accent', label: 'Validating...' },
    ready: { variant: 'accent', label: 'Ready' },
    running: { variant: 'warning', label: 'Running' },
    done: { variant: 'success', label: 'Done' },
    failed: { variant: 'danger', label: 'Failed' },
    cancelled: { variant: 'default', label: 'Cancelled' },
  };
  const m = map[s] ?? { variant: 'default' as const, label: s };
  return <Badge variant={m.variant}>{m.label}</Badge>;
};

const itemStatusBadge = (s: string) => {
  const map: Record<string, { variant: 'default' | 'success' | 'warning' | 'danger' | 'accent'; label: string }> = {
    pending: { variant: 'default', label: 'Pending' },
    valid: { variant: 'accent', label: 'Valid' },
    invalid: { variant: 'danger', label: 'Invalid' },
    ready: { variant: 'accent', label: 'Ready' },
    running: { variant: 'warning', label: 'Running' },
    success: { variant: 'success', label: 'Success' },
    failed: { variant: 'danger', label: 'Failed' },
    skipped: { variant: 'default', label: 'Skipped' },
    cancelled: { variant: 'default', label: 'Cancelled' },
  };
  const m = map[s] ?? { variant: 'default' as const, label: s };
  return <Badge variant={m.variant}>{m.label}</Badge>;
};

// ═══════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════
export default function DeploymentPage() {
  const [activeTab, setActiveTab] = useState<'zabbix' | 'tokens' | 'browser'>('zabbix');

  return (
    <>
      <TopBar title="Deployment" />
      <div className="p-6 space-y-4 animate-fade-in">
        <TabBar
          tabs={[
            { key: 'zabbix' as const, label: 'Zabbix DAT Deploy', icon: <Server style={{ width: '13px', height: '13px' }} /> },
            { key: 'browser' as const, label: 'Browser Mode (Firewall Bypass)', icon: <Monitor style={{ width: '13px', height: '13px' }} /> },
            { key: 'tokens' as const, label: 'Enrollment Tokens', icon: <Key style={{ width: '13px', height: '13px' }} /> },
          ]}
          active={activeTab}
          onChange={setActiveTab}
        />

        {activeTab === 'zabbix' && <ZabbixDeployTab />}
        {activeTab === 'browser' && <BrowserDeployTab />}
        {activeTab === 'tokens' && <EnrollmentTokensTab />}
      </div>
    </>
  );
}

// ═══════════════════════════════════════════
// ZABBIX DEPLOY TAB
// ═══════════════════════════════════════════
function ZabbixDeployTab() {
  const [batches, setBatches] = useState<DeployBatch[]>([]);
  const [loading, setLoading] = useState(true);
  const [showImport, setShowImport] = useState(false);
  const [selectedBatch, setSelectedBatch] = useState<string | null>(null);
  const [items, setItems] = useState<DeployItem[]>([]);
  const [itemsLoading, setItemsLoading] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Import form state
  const [csvContent, setCsvContent] = useState('');
  const [fileBase64, setFileBase64] = useState('');
  const [filename, setFilename] = useState('');
  const [mode, setMode] = useState<'dry_run' | 'live'>('dry_run');
  const [zabbixUrl, setZabbixUrl] = useState('');
  const [zabbixUser, setZabbixUser] = useState('');
  const [zabbixPassword, setZabbixPassword] = useState('');
  const [zabbixScript, setZabbixScript] = useState('Reap3r Enrollment');
  const [serverUrl, setServerUrl] = useState('');
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState('');

  const toBase64 = (buffer: ArrayBuffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
      binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
  };

  const loadBatches = useCallback(async () => {
    try {
      const res = await api.deploy.batches();
      setBatches(res.data);
    } catch { } finally {
      setLoading(false);
    }
  }, []);

  const loadItems = useCallback(async (batchId: string) => {
    setItemsLoading(true);
    try {
      const res = await api.deploy.items(batchId);
      setItems(res.data);
    } catch { } finally {
      setItemsLoading(false);
    }
  }, []);

  useEffect(() => { loadBatches(); }, [loadBatches]);

  // Poll for updates when viewing a running batch
  useEffect(() => {
    if (selectedBatch) {
      const batch = batches.find(b => b.batch_id === selectedBatch);
      if (batch && ['running', 'validating'].includes(batch.status)) {
        pollRef.current = setInterval(() => {
          loadBatches();
          loadItems(selectedBatch);
        }, 5000);
        return () => { if (pollRef.current) clearInterval(pollRef.current); };
      }
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [selectedBatch, batches, loadBatches, loadItems]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    const lower = file.name.toLowerCase();
    if (lower.endsWith('.xlsx') || lower.endsWith('.xls')) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        const result = ev.target?.result as ArrayBuffer;
        setFileBase64(toBase64(result));
        setCsvContent('');
      };
      reader.readAsArrayBuffer(file);
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      setCsvContent(ev.target?.result as string);
      setFileBase64('');
    };
    reader.readAsText(file);
  };

  const handleImport = async () => {
    if ((!csvContent && !fileBase64) || !zabbixUrl || !zabbixUser || !zabbixPassword || !serverUrl) {
      setImportError('All fields are required');
      return;
    }
    setImporting(true);
    setImportError('');
    try {
      const result = await api.deploy.import({
        csv_content: csvContent || undefined,
        file_base64: fileBase64 || undefined,
        filename,
        mode,
        zabbix_url: zabbixUrl,
        zabbix_user: zabbixUser,
        zabbix_password: zabbixPassword,
        zabbix_script: zabbixScript,
        server_url: serverUrl,
      });
      setShowImport(false);
      setCsvContent('');
      setFileBase64('');
      setFilename('');
      loadBatches();
      // Auto-select the new batch
      if (result.batch_id) {
        setSelectedBatch(result.batch_id);
        loadItems(result.batch_id);
      }
    } catch (err: any) {
      setImportError(err.message ?? 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  const handleValidate = async (batchId: string) => {
    const pw = prompt('Enter Zabbix password to validate:');
    if (!pw) return;
    try {
      await api.deploy.validate(batchId, pw);
      loadBatches();
      loadItems(batchId);
    } catch (err: any) {
      alert(`Validation failed: ${err.message}`);
    }
  };

  const handleStart = async (batchId: string) => {
    if (!confirm('Start live deployment? This will execute scripts via Zabbix.')) return;
    try {
      await api.deploy.start(batchId);
      loadBatches();
      loadItems(batchId);
    } catch (err: any) {
      alert(`Start failed: ${err.message}`);
    }
  };

  const handleRetry = async (batchId: string) => {
    try {
      const res = await api.deploy.retry(batchId);
      alert(`${res.retried} items queued for retry`);
      loadBatches();
      loadItems(batchId);
    } catch (err: any) {
      alert(`Retry failed: ${err.message}`);
    }
  };

  const handleCancel = async (batchId: string) => {
    if (!confirm('Cancel this batch? Running scripts cannot be stopped.')) return;
    try {
      await api.deploy.cancel(batchId);
      loadBatches();
      loadItems(batchId);
    } catch (err: any) {
      alert(`Cancel failed: ${err.message}`);
    }
  };

  const exportCsv = () => {
    if (items.length === 0) return;
    const headers = ['row', 'zabbix_host', 'dat', 'status', 'attempts', 'error', 'callback_status', 'callback_exit'];
    const csv = [headers.join(','), ...items.map(i =>
      [i.row_number, i.zabbix_host, i.dat, i.status, i.attempt_count,
       `"${(i.last_error ?? i.validation_error ?? '').replace(/"/g, '""')}"`,
       i.callback_status ?? '', i.callback_exit ?? ''].join(',')
    )].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `deploy-report-${selectedBatch?.slice(0, 8)}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const activeBatch = batches.find(b => b.batch_id === selectedBatch);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
            <Server className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
          </div>
          <div>
            <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Zabbix DAT Deployment</h3>
            <p className="text-[10px] text-reap3r-muted">Import CSV/XLSX → Validate → Execute via Zabbix</p>
          </div>
        </div>
        <Button size="sm" onClick={() => setShowImport(true)}>
          <Upload style={{ width: '12px', height: '12px', marginRight: '4px' }} />Import CSV/XLSX
        </Button>
      </div>

      {/* Batch List */}
      <Card>
        {loading ? (
          <div className="space-y-2">{[...Array(3)].map((_, i) => <div key={i} className="bg-reap3r-surface border border-reap3r-border rounded-xl h-16 animate-pulse" />)}</div>
        ) : batches.length === 0 ? (
          <EmptyState icon={<FileSpreadsheet style={{ width: '28px', height: '28px' }} />} title="No batches" description="Import a CSV file to start a Zabbix deployment batch." />
        ) : (
          <div className="space-y-2">
            {batches.map(batch => (
              <div key={batch.batch_id} onClick={() => { setSelectedBatch(batch.batch_id); loadItems(batch.batch_id); }}
                className={`flex items-center gap-3 px-4 py-3 border rounded-xl cursor-pointer transition-all
                  ${selectedBatch === batch.batch_id
                    ? 'bg-white/8 border-white/20'
                    : 'bg-reap3r-surface/60 border-reap3r-border/60 hover:border-reap3r-border-light'}`}>
                <div className="w-8 h-8 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center shrink-0">
                  <FileSpreadsheet className="text-reap3r-light" style={{ width: '12px', height: '12px' }} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] font-semibold text-white truncate">{batch.filename}</p>
                  <p className="text-[10px] text-reap3r-muted">
                    {batch.total_items} items &middot; {batch.mode === 'dry_run' ? 'Dry Run' : 'Live'} &middot; {new Date(batch.created_at).toLocaleString()}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {batch.success_count > 0 && <span className="text-[10px] text-reap3r-success font-mono">{batch.success_count}✓</span>}
                  {batch.failed_count > 0 && <span className="text-[10px] text-reap3r-danger font-mono">{batch.failed_count}✗</span>}
                  {batchStatusBadge(batch.status)}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Batch Detail */}
      {activeBatch && (
        <Card>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">{activeBatch.filename}</h3>
              <p className="text-[10px] text-reap3r-muted">Batch {activeBatch.batch_id.slice(0, 8)} &middot; {activeBatch.mode === 'dry_run' ? 'Dry Run' : 'Live'}</p>
            </div>
            <div className="flex items-center gap-2">
              {activeBatch.status === 'created' && (
                <Button size="sm" variant="primary" onClick={() => handleValidate(activeBatch.batch_id)}>
                  <Shield style={{ width: '12px', height: '12px', marginRight: '4px' }} />Validate
                </Button>
              )}
              {activeBatch.status === 'ready' && activeBatch.mode === 'live' && (
                <Button size="sm" variant="primary" onClick={() => handleStart(activeBatch.batch_id)}>
                  <Play style={{ width: '12px', height: '12px', marginRight: '4px' }} />Start
                </Button>
              )}
              {['running', 'done', 'failed'].includes(activeBatch.status) && activeBatch.failed_count > 0 && (
                <Button size="sm" variant="secondary" onClick={() => handleRetry(activeBatch.batch_id)}>
                  <RotateCcw style={{ width: '12px', height: '12px', marginRight: '4px' }} />Retry Failed
                </Button>
              )}
              {['created', 'ready', 'running'].includes(activeBatch.status) && (
                <Button size="sm" variant="danger" onClick={() => handleCancel(activeBatch.batch_id)}>
                  <XCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} />Cancel
                </Button>
              )}
              <Button size="sm" variant="ghost" onClick={exportCsv} disabled={items.length === 0}>
                <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />Export
              </Button>
              <Button size="sm" variant="ghost" onClick={() => loadItems(activeBatch.batch_id)}>
                <RefreshCw style={{ width: '12px', height: '12px' }} />
              </Button>
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-6 gap-2 mb-4">
            {[
              { label: 'Total', value: activeBatch.total_items, icon: Activity },
              { label: 'Valid', value: activeBatch.valid_count, icon: CheckCircle2 },
              { label: 'Invalid', value: activeBatch.invalid_count, icon: AlertTriangle },
              { label: 'Success', value: activeBatch.success_count, icon: Check },
              { label: 'Failed', value: activeBatch.failed_count, icon: XCircle },
              { label: 'Skipped', value: activeBatch.skipped_count, icon: Clock },
            ].map(s => (
              <div key={s.label} className="flex flex-col items-center p-2 bg-reap3r-surface/40 border border-reap3r-border/40 rounded-lg">
                <s.icon style={{ width: '12px', height: '12px' }} className="text-reap3r-muted mb-1" />
                <span className="text-[14px] font-bold text-white">{s.value}</span>
                <span className="text-[9px] text-reap3r-muted uppercase tracking-wider">{s.label}</span>
              </div>
            ))}
          </div>

          {activeBatch.error && (
            <div className="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg">
              <p className="text-[11px] text-red-400">{activeBatch.error}</p>
            </div>
          )}

          {/* Items table */}
          {itemsLoading ? (
            <div className="space-y-1">{[...Array(5)].map((_, i) => <div key={i} className="h-10 bg-reap3r-surface rounded animate-pulse" />)}</div>
          ) : items.length === 0 ? (
            <p className="text-[11px] text-reap3r-muted text-center py-4">No items</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[11px]">
                <thead>
                  <tr className="text-left text-reap3r-muted uppercase tracking-wider border-b border-reap3r-border/40">
                    <th className="pb-2 pr-3">#</th>
                    <th className="pb-2 pr-3">Host</th>
                    <th className="pb-2 pr-3">DAT</th>
                    <th className="pb-2 pr-3">Status</th>
                    <th className="pb-2 pr-3">Attempts</th>
                    <th className="pb-2 pr-3">Callback</th>
                    <th className="pb-2">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map(item => (
                    <tr key={item.id} className="border-b border-reap3r-border/20 hover:bg-white/3 transition-colors">
                      <td className="py-2 pr-3 text-reap3r-muted font-mono">{item.row_number}</td>
                      <td className="py-2 pr-3 text-white font-mono">{item.zabbix_host}</td>
                      <td className="py-2 pr-3 text-reap3r-light font-mono text-[10px]">{item.dat.slice(0, 12)}...</td>
                      <td className="py-2 pr-3">{itemStatusBadge(item.status)}</td>
                      <td className="py-2 pr-3 text-reap3r-muted">{item.attempt_count}</td>
                      <td className="py-2 pr-3">
                        {item.callback_received ? (
                          <span className="text-reap3r-success flex items-center gap-1">
                            <Check style={{ width: '10px', height: '10px' }} />
                            {item.callback_status} ({item.callback_exit})
                          </span>
                        ) : item.status === 'running' ? (
                          <span className="text-reap3r-muted">Waiting...</span>
                        ) : null}
                      </td>
                      <td className="py-2 text-red-400 text-[10px] max-w-[200px] truncate" title={item.last_error ?? item.validation_error ?? ''}>
                        {item.last_error ?? item.validation_error ?? ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* Import Modal */}
      <Modal open={showImport} onClose={() => setShowImport(false)} title="Import CSV/XLSX for Zabbix Deploy" maxWidth="max-w-2xl">
        <div className="space-y-4">
          {/* File upload */}
          <div>
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">CSV/XLSX File</label>
            <div className="flex items-center gap-2">
              <label className="flex-1 flex items-center justify-center gap-2 px-4 py-3 border-2 border-dashed border-reap3r-border rounded-xl cursor-pointer hover:border-white/20 transition-colors">
                <Upload style={{ width: '14px', height: '14px' }} className="text-reap3r-muted" />
                <span className="text-[11px] text-reap3r-muted">{filename || 'Choose CSV/XLSX file (zabbix_host, dat)'}</span>
                <input type="file" accept=".csv,.txt,.tsv,.xlsx,.xls" onChange={handleFileUpload} className="hidden" />
              </label>
            </div>
          </div>

          {/* Mode */}
          <div>
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">Mode</label>
            <div className="flex gap-2">
              <button onClick={() => setMode('dry_run')}
                className={`flex-1 px-3 py-2 rounded-lg text-[11px] font-semibold border transition-all
                  ${mode === 'dry_run' ? 'bg-white/10 border-white/20 text-white' : 'bg-reap3r-surface border-reap3r-border text-reap3r-muted hover:border-white/15'}`}>
                <Shield style={{ width: '12px', height: '12px', display: 'inline', marginRight: '4px' }} />Dry Run
              </button>
              <button onClick={() => setMode('live')}
                className={`flex-1 px-3 py-2 rounded-lg text-[11px] font-semibold border transition-all
                  ${mode === 'live' ? 'bg-orange-500/20 border-orange-500/40 text-orange-300' : 'bg-reap3r-surface border-reap3r-border text-reap3r-muted hover:border-white/15'}`}>
                <Play style={{ width: '12px', height: '12px', display: 'inline', marginRight: '4px' }} />Live
              </button>
            </div>
          </div>

          {/* Zabbix config */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">Zabbix URL</label>
              <input value={zabbixUrl} onChange={e => setZabbixUrl(e.target.value)} placeholder="https://zabbix.company.com"
                className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
            </div>
            <div>
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">Zabbix Script Name</label>
              <input value={zabbixScript} onChange={e => setZabbixScript(e.target.value)} placeholder="Reap3r Enrollment"
                className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
            </div>
            <div>
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">Zabbix User</label>
              <input value={zabbixUser} onChange={e => setZabbixUser(e.target.value)} placeholder="Admin"
                className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
            </div>
            <div>
              <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">Zabbix Password</label>
              <input value={zabbixPassword} onChange={e => setZabbixPassword(e.target.value)} type="password" placeholder="••••••••"
                className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em] mb-1">Reap3r Server URL (for callback)</label>
            <input value={serverUrl} onChange={e => setServerUrl(e.target.value)} placeholder="https://reap3r.company.com"
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20" />
          </div>

          {importError && (
            <div className="px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg">
              <p className="text-[11px] text-red-400">{importError}</p>
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowImport(false)}>Cancel</Button>
            <Button onClick={handleImport} loading={importing} disabled={(!csvContent && !fileBase64) || !zabbixUrl || !zabbixUser || !zabbixPassword || !serverUrl}>
              <Upload style={{ width: '12px', height: '12px', marginRight: '4px' }} />Import & Create Batch
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ═══════════════════════════════════════════
// ENROLLMENT TOKENS TAB (migrated from old page)
// ═══════════════════════════════════════════
function EnrollmentTokensTab() {
  const [tokens, setTokens] = useState<any[]>([]);
  const [commands, setCommands] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newTokenName, setNewTokenName] = useState('');
  const [creating, setCreating] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    api.enrollment.tokens.list().then(r => { setTokens(r.data); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const createToken = async () => {
    if (!newTokenName.trim()) return;
    setCreating(true);
    try {
      await api.enrollment.tokens.create({ name: newTokenName, max_uses: 0 });
      const res = await api.enrollment.tokens.list();
      setTokens(res.data); setNewTokenName(''); setShowCreate(false);
    } finally { setCreating(false); }
  };

  const revokeToken = async (id: string) => {
    if (!confirm('Revoke this token?')) return;
    await api.enrollment.tokens.revoke(id);
    const res = await api.enrollment.tokens.list();
    setTokens(res.data);
    if (commands) setCommands(null);
  };

  const loadCommands = async (id: string) => {
    try { const cmds = await api.enrollment.tokens.commands(id); setCommands(cmds); } catch {}
  };

  const copy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Deployment Commands */}
      <Card>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
            <Terminal className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
          </div>
          <div>
            <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Deploy Commands</h3>
            <p className="text-[10px] text-reap3r-muted">One-liner scripts to install agents on endpoints</p>
          </div>
        </div>

        {commands ? (
          <div className="space-y-3">
            <CommandBlock label="Windows (PowerShell)" icon={<MonitorIcon style={{ width: '12px', height: '12px' }} />}
              command={commands.windows_powershell} onCopy={() => copy(commands.windows_powershell, 'windows')} copied={copiedField === 'windows'} />
            <CommandBlock label="Linux (one-liner)" icon={<Terminal style={{ width: '12px', height: '12px' }} />}
              command={commands.linux_oneliner ?? commands.linux_bash} onCopy={() => copy(commands.linux_oneliner ?? commands.linux_bash, 'linux')} copied={copiedField === 'linux'} />
          </div>
        ) : tokens.filter(t => !t.revoked).length > 0 ? (
          <div className="space-y-2">
            <p className="text-[10px] text-reap3r-muted uppercase tracking-[0.08em] font-bold">Select a token to generate commands</p>
            <div className="flex gap-2 flex-wrap">
              {tokens.filter(t => !t.revoked).map(t => (
                <button key={t.id} onClick={() => loadCommands(t.id)}
                  className="flex items-center gap-2 px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-xl text-[11px] text-reap3r-light hover:text-white hover:border-reap3r-border-light transition-all">
                  <Key style={{ width: '11px', height: '11px' }} /> {t.name}
                  <ArrowRight style={{ width: '10px', height: '10px' }} className="text-reap3r-muted" />
                </button>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-[11px] text-reap3r-muted">Create an enrollment token first.</p>
        )}
      </Card>

      {/* Enrollment Tokens */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
              <Key className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
            </div>
            <div>
              <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Enrollment Tokens</h3>
              <p className="text-[10px] text-reap3r-muted">Tokens used by agents during enrollment</p>
            </div>
          </div>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus style={{ width: '12px', height: '12px', marginRight: '4px' }} />Create
          </Button>
        </div>

        {loading ? (
          <div className="space-y-2">
            {[...Array(2)].map((_, i) => <div key={i} className="bg-reap3r-surface border border-reap3r-border rounded-xl h-14 animate-pulse" />)}
          </div>
        ) : tokens.length === 0 ? (
          <EmptyState icon={<Key style={{ width: '28px', height: '28px' }} />} title="No tokens" description="Create an enrollment token to start deploying agents." />
        ) : (
          <div className="space-y-2">
            {tokens.map(token => (
              <div key={token.id} className="flex items-center gap-3 px-4 py-3 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl group hover:border-reap3r-border-light transition-all">
                <div className="w-8 h-8 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center shrink-0">
                  <Key className="text-reap3r-light" style={{ width: '12px', height: '12px' }} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] font-semibold text-white">{token.name}</p>
                  <p className="text-[10px] text-reap3r-muted font-mono truncate">{token.token}</p>
                </div>
                <Badge variant="default">{token.use_count}{token.max_uses > 0 ? `/${token.max_uses}` : ''} uses</Badge>
                {token.revoked ? (
                  <Badge variant="danger">Revoked</Badge>
                ) : (
                  <div className="flex items-center gap-1.5">
                    <button onClick={() => copy(token.token, token.id)}
                      className="p-1.5 text-reap3r-muted hover:text-white hover:bg-reap3r-hover rounded-lg transition-all">
                      {copiedField === token.id
                        ? <Check className="text-reap3r-success" style={{ width: '12px', height: '12px' }} />
                        : <Copy style={{ width: '12px', height: '12px' }} />}
                    </button>
                    <button onClick={() => revokeToken(token.id)}
                      className="p-1.5 text-reap3r-muted hover:text-reap3r-danger hover:bg-reap3r-danger/10 rounded-lg transition-all opacity-0 group-hover:opacity-100">
                      <Trash2 style={{ width: '12px', height: '12px' }} />
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Agent Downloads */}
      <Card>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-white/6 border border-white/10 flex items-center justify-center">
            <Download className="text-reap3r-light" style={{ width: '16px', height: '16px' }} />
          </div>
          <div>
            <h3 className="text-[12px] font-bold text-white uppercase tracking-[0.08em]">Agent Downloads</h3>
            <p className="text-[10px] text-reap3r-muted">Pre-built agent binaries</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            { os: 'Windows', icon: MonitorIcon, desc: 'EXE/MSI installer (signed)', href: '/api/agent-binary/download?os=windows&arch=x86_64', color: 'text-blue-400' },
            { os: 'Linux', icon: Terminal, desc: 'Binary (sha256 + signature)', href: '/api/agent-binary/download?os=linux&arch=x86_64', color: 'text-green-400' },
          ].map(d => (
            <a key={d.os} href={d.href} className="block group">
              <div className="flex items-center gap-3 p-4 bg-reap3r-surface/60 border border-reap3r-border/60 rounded-xl hover:border-reap3r-border-light transition-all">
                <div className="w-10 h-10 rounded-xl bg-white/4 border border-white/8 flex items-center justify-center">
                  <d.icon className={d.color} style={{ width: '16px', height: '16px' }} />
                </div>
                <div className="flex-1">
                  <p className="text-[12px] font-semibold text-white">{d.os} Agent</p>
                  <p className="text-[10px] text-reap3r-muted">{d.desc}</p>
                </div>
                <Download className="text-reap3r-muted group-hover:text-white transition-colors" style={{ width: '14px', height: '14px' }} />
              </div>
            </a>
          ))}
        </div>
      </Card>

      {/* Create Token Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Enrollment Token">
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.16em]">Token Name</label>
            <input value={newTokenName} onChange={e => setNewTokenName(e.target.value)} placeholder="Production, Lab, Client..."
              className="w-full px-3 py-2.5 bg-reap3r-surface border border-reap3r-border rounded-lg text-sm text-white placeholder:text-reap3r-muted/40 focus:outline-none focus:ring-1 focus:ring-white/20 focus:border-white/20" />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={createToken} disabled={!newTokenName.trim() || creating}>Create</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

function CommandBlock({ label, icon, command, onCopy, copied }: {
  label: string; icon: React.ReactNode; command: string; onCopy: () => void; copied: boolean;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] text-reap3r-muted font-bold uppercase tracking-[0.08em] flex items-center gap-1.5">{icon} {label}</span>
        <button onClick={onCopy} className="text-[10px] text-reap3r-light hover:text-white flex items-center gap-1 transition-colors">
          {copied ? <><Check className="text-reap3r-success" style={{ width: '10px', height: '10px' }} /> Copied</> : <><Copy style={{ width: '10px', height: '10px' }} /> Copy</>}
        </button>
      </div>
      <pre className="code-block px-4 py-3 text-[11px] overflow-x-auto whitespace-pre-wrap break-all">
        {command}
      </pre>
    </div>
  );
}
