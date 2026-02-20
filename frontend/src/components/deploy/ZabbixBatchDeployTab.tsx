'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Card, Button, Badge } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Upload,
  Play,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  RotateCcw,
  XCircle,
  Download,
  Server,
} from 'lucide-react';

type DeployBatch = {
  batch_id: string;
  mode: 'dry_run' | 'live';
  status: string;
  total_items: number;
  valid_count: number;
  invalid_count: number;
  success_count: number;
  failed_count: number;
  skipped_count: number;
  error?: string | null;
};

type DeployItem = {
  id: string;
  row_number: number;
  zabbix_host: string;
  status: string;
  attempt_count: number;
  validation_error?: string | null;
  last_error?: string | null;
  callback_received?: boolean;
  callback_status?: string | null;
  callback_message?: string | null;
};

type ImportError = {
  row: number;
  zabbix_host?: string;
  dat?: string;
  error: string;
};

type ImportResult = {
  batch_id: string;
  total: number;
  valid: number;
  invalid: number;
  duplicates: number;
  errors: ImportError[];
};

const POLL_MS = 3500;

function statusBadge(status: string) {
  const s = (status || '').toLowerCase();
  if (s === 'success' || s === 'done') return <Badge variant="success">{status}</Badge>;
  if (s === 'failed' || s === 'invalid' || s === 'cancelled') return <Badge variant="danger">{status}</Badge>;
  if (s === 'running' || s === 'validating') return <Badge variant="warning">{status}</Badge>;
  return <Badge variant="default">{status || 'unknown'}</Badge>;
}

function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('Impossible de lire le fichier'));
    reader.onload = () => {
      const result = reader.result;
      if (!(result instanceof ArrayBuffer)) {
        reject(new Error('Format de fichier non supporté'));
        return;
      }

      let binary = '';
      const bytes = new Uint8Array(result);
      const chunk = 0x8000;
      for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
      }
      resolve(btoa(binary));
    };
    reader.readAsArrayBuffer(file);
  });
}

export function ZabbixBatchDeployTab({
  onSwitchToBrowserMode,
}: {
  onSwitchToBrowserMode?: () => void;
}) {
  const [mode, setMode] = useState<'dry_run' | 'live'>('live');
  const [zabbixUrl, setZabbixUrl] = useState('https://prod-zabbix.hypervision.fr:8081');
  const [zabbixUser, setZabbixUser] = useState('massvision');
  const [zabbixPassword, setZabbixPassword] = useState('');
  const [zabbixScript, setZabbixScript] = useState('Reap3rEnroll');
  const [serverUrl, setServerUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);

  const [isImporting, setIsImporting] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const [isRetrying, setIsRetrying] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [batchId, setBatchId] = useState<string | null>(null);
  const [batch, setBatch] = useState<DeployBatch | null>(null);
  const [items, setItems] = useState<DeployItem[]>([]);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);

  const backendCannotReachZabbix = useMemo(() => {
    const msg = (errorMsg || '').toLowerCase();
    return msg.includes('und_err_connect_timeout') || msg.includes('cannot reach zabbix endpoint');
  }, [errorMsg]);

  useEffect(() => {
    if (typeof window !== 'undefined' && !serverUrl) {
      setServerUrl(window.location.origin);
    }
  }, [serverUrl]);

  const refreshBatch = useCallback(async () => {
    if (!batchId) return;
    const [batchRes, itemsRes] = await Promise.all([
      api.deploy.batch(batchId),
      api.deploy.items(batchId),
    ]);
    setBatch(batchRes as DeployBatch);
    setItems((itemsRes?.data ?? []) as DeployItem[]);
  }, [batchId]);

  useEffect(() => {
    if (!batchId) return;
    let timer: ReturnType<typeof setInterval> | null = null;
    let mounted = true;

    const tick = async () => {
      if (!mounted) return;
      try {
        await refreshBatch();
      } catch {
        // Keep UI responsive even when one poll fails.
      }
    };

    tick();
    timer = setInterval(() => {
      const status = (batch?.status || '').toLowerCase();
      const shouldPoll = ['created', 'validating', 'ready', 'running'].includes(status);
      if (shouldPoll) tick();
    }, POLL_MS);

    return () => {
      mounted = false;
      if (timer) clearInterval(timer);
    };
  }, [batchId, batch?.status, refreshBatch]);

  const stats = useMemo(() => {
    if (!batch) {
      return { total: 0, valid: 0, invalid: 0, success: 0, failed: 0, skipped: 0 };
    }
    return {
      total: Number(batch.total_items || 0),
      valid: Number(batch.valid_count || 0),
      invalid: Number(batch.invalid_count || 0),
      success: Number(batch.success_count || 0),
      failed: Number(batch.failed_count || 0),
      skipped: Number(batch.skipped_count || 0),
    };
  }, [batch]);

  const importFile = async () => {
    if (!file) {
      setErrorMsg('Charge un fichier CSV/XLSX avant import.');
      return;
    }
    setErrorMsg(null);
    setIsImporting(true);
    setImportResult(null);
    setBatch(null);
    setItems([]);

    try {
      const base64 = await toBase64(file);
      const result = (await api.deploy.import({
        file_base64: base64,
        filename: file.name,
        mode,
        zabbix_url: zabbixUrl.trim(),
        zabbix_user: zabbixUser.trim(),
        zabbix_password: zabbixPassword.trim() || undefined,
        zabbix_script: zabbixScript.trim() || 'Reap3rEnroll',
        server_url: serverUrl.trim(),
      })) as ImportResult;

      setImportResult(result);
      setBatchId(result.batch_id);
      await refreshBatch();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Import échoué');
    } finally {
      setIsImporting(false);
    }
  };

  const validateBatch = async () => {
    if (!batchId) return;
    setErrorMsg(null);
    setIsValidating(true);
    try {
      await api.deploy.validate(batchId, zabbixPassword.trim());
      await refreshBatch();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Validation échouée');
    } finally {
      setIsValidating(false);
    }
  };

  const startBatch = async () => {
    if (!batchId) return;
    setErrorMsg(null);
    setIsStarting(true);
    try {
      await api.deploy.start(batchId);
      await refreshBatch();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Démarrage échoué');
    } finally {
      setIsStarting(false);
    }
  };

  const retryBatch = async () => {
    if (!batchId) return;
    setErrorMsg(null);
    setIsRetrying(true);
    try {
      await api.deploy.retry(batchId);
      await refreshBatch();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Retry échoué');
    } finally {
      setIsRetrying(false);
    }
  };

  const cancelBatch = async () => {
    if (!batchId) return;
    setErrorMsg(null);
    setIsCancelling(true);
    try {
      await api.deploy.cancel(batchId);
      await refreshBatch();
    } catch (err: any) {
      setErrorMsg(err?.message || 'Annulation échouée');
    } finally {
      setIsCancelling(false);
    }
  };

  const manualRefresh = async () => {
    if (!batchId) return;
    setIsRefreshing(true);
    try {
      await refreshBatch();
    } finally {
      setIsRefreshing(false);
    }
  };

  const exportItemsCsv = () => {
    if (items.length === 0) return;
    const header = ['row', 'zabbix_host', 'status', 'attempt_count', 'callback_received', 'error', 'callback_message'];
    const rows = items.map((item) => [
      item.row_number,
      item.zabbix_host,
      item.status,
      item.attempt_count,
      item.callback_received ? 'yes' : 'no',
      (item.validation_error || item.last_error || '').replace(/"/g, '""'),
      (item.callback_message || '').replace(/"/g, '""'),
    ]);
    const csv = [header.join(','), ...rows.map((r) => r.map((v) => `"${String(v)}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `deploy-batch-${batchId || 'report'}.csv`;
    a.click();
  };

  const canStart = batch?.status === 'ready' && batch?.mode === 'live';
  const canRetry = batch?.status === 'running' || batch?.status === 'failed' || batch?.status === 'done';
  const canCancel = batch?.status === 'created' || batch?.status === 'validating' || batch?.status === 'ready' || batch?.status === 'running';

  return (
    <div className="space-y-4">
      <Card className="p-4 border-l-4 border-l-emerald-500 bg-emerald-500/5">
        <div className="flex items-start gap-2">
          <Server className="w-4 h-4 text-emerald-400 mt-0.5" />
          <div className="text-[11px] text-emerald-300">
            <strong>Mode backend batch actif</strong> : import, validation Zabbix, exécution worker, callback preuve.
          </div>
        </div>
      </Card>

      <Card>
        <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.08em] mb-3">Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as 'dry_run' | 'live')}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white"
            >
              <option value="live">Live</option>
              <option value="dry_run">Dry-run</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">URL Zabbix</label>
            <input
              value={zabbixUrl}
              onChange={(e) => setZabbixUrl(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white"
            />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Utilisateur Zabbix</label>
            <input
              value={zabbixUser}
              onChange={(e) => setZabbixUser(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white"
            />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Mot de passe / token API Zabbix</label>
            <input
              type="password"
              value={zabbixPassword}
              onChange={(e) => setZabbixPassword(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white"
            />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Script global Zabbix</label>
            <input
              value={zabbixScript}
              onChange={(e) => setZabbixScript(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white"
            />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">URL serveur Reap3r</label>
            <input
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white"
            />
          </div>
        </div>
      </Card>

      <Card>
        <div className="flex flex-wrap gap-2 items-center">
          <label className="flex items-center gap-2 px-3 py-2 border border-dashed border-reap3r-border rounded-lg cursor-pointer text-[11px] text-reap3r-muted hover:text-white">
            <Upload className="w-3 h-3" />
            {file ? file.name : 'Charger CSV/XLSX (zabbix_host + dat)'}
            <input
              type="file"
              accept=".csv,.tsv,.txt,.xlsx,.xls"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>

          <Button onClick={importFile} disabled={isImporting || !file}>
            {isImporting ? <RotateCcw className="w-3 h-3 mr-1 animate-spin" /> : <Upload className="w-3 h-3 mr-1" />}
            Import
          </Button>

          <Button variant="secondary" onClick={validateBatch} disabled={!batchId || isValidating}>
            {isValidating ? <RotateCcw className="w-3 h-3 mr-1 animate-spin" /> : <CheckCircle2 className="w-3 h-3 mr-1" />}
            Valider (Dry-run)
          </Button>

          <Button onClick={startBatch} disabled={!canStart || isStarting}>
            {isStarting ? <RotateCcw className="w-3 h-3 mr-1 animate-spin" /> : <Play className="w-3 h-3 mr-1" />}
            Démarrer
          </Button>

          <Button variant="secondary" onClick={retryBatch} disabled={!canRetry || isRetrying}>
            {isRetrying ? <RotateCcw className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}
            Retry failed
          </Button>

          <Button variant="danger" onClick={cancelBatch} disabled={!canCancel || isCancelling}>
            {isCancelling ? <RotateCcw className="w-3 h-3 mr-1 animate-spin" /> : <XCircle className="w-3 h-3 mr-1" />}
            Cancel
          </Button>

          <Button variant="ghost" onClick={manualRefresh} disabled={!batchId || isRefreshing}>
            {isRefreshing ? <RotateCcw className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}
            Refresh
          </Button>

          <Button variant="ghost" onClick={exportItemsCsv} disabled={items.length === 0}>
            <Download className="w-3 h-3 mr-1" />
            Export CSV
          </Button>
        </div>
      </Card>

      {errorMsg && (
        <Card className="p-3 border border-red-500/40 bg-red-500/10 text-red-300 text-[11px]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-3 h-3" />
            {errorMsg}
          </div>
          {backendCannotReachZabbix && (
            <div className="mt-3">
              <Button
                size="sm"
                onClick={() => onSwitchToBrowserMode?.()}
                className="text-[11px]"
              >
                Basculer en Browser Direct (fonctionne sans accès VPS vers Zabbix)
              </Button>
            </div>
          )}
        </Card>
      )}

      {importResult && (
        <Card className="p-3 text-[11px]">
          <div className="text-white font-semibold mb-2">Import batch: {importResult.batch_id}</div>
          <div className="text-reap3r-muted">
            Total: {importResult.total} | Valides: {importResult.valid} | Invalides: {importResult.invalid} | Doublons: {importResult.duplicates}
          </div>
          {importResult.errors?.length > 0 && (
            <div className="mt-2 max-h-40 overflow-auto border border-white/10 rounded p-2 bg-black/20">
              {importResult.errors.slice(0, 100).map((e, idx) => (
                <div key={idx} className="text-red-300">
                  Ligne {e.row}: {e.zabbix_host || '-'} - {e.error}
                </div>
              ))}
              {importResult.errors.length > 100 && (
                <div className="text-reap3r-muted">... {importResult.errors.length - 100} erreurs supplémentaires</div>
              )}
            </div>
          )}
        </Card>
      )}

      {batch && (
        <Card className="p-3 text-[11px]">
          <div className="flex items-center gap-3 mb-2">
            <div className="text-white font-semibold">Batch {batch.batch_id}</div>
            {statusBadge(batch.status)}
            <span className="text-reap3r-muted">mode: {batch.mode}</span>
          </div>
          {batch.error && <div className="text-red-300 mb-2">{batch.error}</div>}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
            <div className="p-2 rounded border border-white/10">Total<br /><strong>{stats.total}</strong></div>
            <div className="p-2 rounded border border-white/10">Valides<br /><strong>{stats.valid}</strong></div>
            <div className="p-2 rounded border border-white/10">Invalides<br /><strong>{stats.invalid}</strong></div>
            <div className="p-2 rounded border border-white/10">Succès<br /><strong>{stats.success}</strong></div>
            <div className="p-2 rounded border border-white/10">Échecs<br /><strong>{stats.failed}</strong></div>
            <div className="p-2 rounded border border-white/10">Skipped<br /><strong>{stats.skipped}</strong></div>
          </div>
        </Card>
      )}

      <Card className="p-0 overflow-hidden">
        <div className="max-h-[430px] overflow-y-auto">
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-reap3r-bg border-b border-white/10">
              <tr className="text-left text-reap3r-muted">
                <th className="px-3 py-2">#</th>
                <th className="px-3 py-2">Host</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Attempts</th>
                <th className="px-3 py-2">Callback</th>
                <th className="px-3 py-2">Erreur / Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {items.map((item) => (
                <tr key={item.id} className="hover:bg-white/5">
                  <td className="px-3 py-2 text-reap3r-muted">{item.row_number}</td>
                  <td className="px-3 py-2 font-mono text-white">{item.zabbix_host}</td>
                  <td className="px-3 py-2">{statusBadge(item.status)}</td>
                  <td className="px-3 py-2">{item.attempt_count}</td>
                  <td className="px-3 py-2">
                    {item.callback_received ? <Badge variant="success">yes</Badge> : <Badge variant="default">no</Badge>}
                  </td>
                  <td className="px-3 py-2 text-white/80">
                    {item.validation_error || item.last_error || item.callback_message || item.callback_status || '-'}
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-12 text-center text-reap3r-muted">
                    Aucun item à afficher.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
