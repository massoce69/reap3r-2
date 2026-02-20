'use client';
import { useEffect, useState, useCallback, useRef } from 'react';
import { TopBar } from '@/components/layout/sidebar';
import { Card, Button, Badge, EmptyState, Modal, TabBar } from '@/components/ui';
import { api } from '@/lib/api';
import {
  Download, Copy, Key, Terminal, Monitor as MonitorIcon, Check,
  Plus, Trash2, ArrowRight, Upload, Play, RotateCcw, XCircle,
  FileSpreadsheet, Server, Shield, Clock, CheckCircle2, AlertTriangle,
  Activity, RefreshCw, Wifi
} from 'lucide-react';
import * as XLSX from 'xlsx';

// ═══════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════
interface LocalItem {
  id: number;
  hostname: string;
  dat: string;
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped';
  message: string;
}

// ═══════════════════════════════════════════
// STATUS BADGE
// ═══════════════════════════════════════════
function StatusBadge({ s }: { s: LocalItem['status'] }) {
  const map = {
    pending:  <Badge variant="default">En attente</Badge>,
    running:  <Badge variant="warning">En cours...</Badge>,
    success:  <Badge variant="success">Succès</Badge>,
    failed:   <Badge variant="danger">Échec</Badge>,
    skipped:  <Badge variant="default">Ignoré</Badge>,
  };
  return map[s] ?? <Badge variant="default">{s}</Badge>;
}

// ═══════════════════════════════════════════
// ZABBIX BROWSER CLIENT
// ═══════════════════════════════════════════
class ZabbixBrowserClient {
  private apiUrl: string;
  private authToken: string | null = null;
  scriptName: string;

  constructor(url: string, script: string) {
    this.apiUrl = url.replace(/\/api_jsonrpc\.php$/, '').replace(/\/$/, '') + '/api_jsonrpc.php';
    this.scriptName = script || 'Reap3rEnroll';
  }

  private async rpc(method: string, params: Record<string, unknown>) {
    const body: Record<string, unknown> = {
      jsonrpc: '2.0', method, params, id: Date.now(),
    };
    if (this.authToken && method !== 'user.login') body.auth = this.authToken;

    const res = await fetch(this.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json-rpc' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    const json = await res.json() as { result?: unknown; error?: { message: string; data: string } };
    if (json.error) throw new Error(`Zabbix: ${json.error.message} — ${json.error.data ?? ''}`);
    return json.result;
  }

  async login(user: string, pass: string) {
    // If it looks like an API token (64 hex chars), use directly
    if (/^[a-f0-9]{64}$/i.test(pass)) {
      this.authToken = pass;
      return;
    }
    this.authToken = await this.rpc('user.login', { user, password: pass }) as string;
  }

  // Récupère la config COMPLÈTE du script de référence qui fonctionne (massvision v5 ou autre)
  private async getReferenceScript(): Promise<Record<string, unknown>> {
    const REF_NAMES = ['massvision v5', 'massvision xefi install', 'install xefi agent', 'agent mass secour', 'agent mass'];
    const all = await this.rpc('script.get', {
      output: 'extend',
    }) as Array<Record<string, unknown>>;

    for (const ref of REF_NAMES) {
      const found = (all || []).find(s => String(s.name).trim().toLowerCase().includes(ref));
      if (found) return found;
    }
    // Fallback : premier script de type shell (type=0)
    const shell = (all || []).find(s => String(s.type) === '0');
    if (shell) return shell;
    return {};
  }

  async getScriptId(): Promise<string> {
    const all = await this.rpc('script.get', {
      output: 'extend',
    }) as Array<Record<string, unknown>>;

    const target = this.scriptName.trim().toLowerCase();
    const match = (all || []).find(s => String(s.name).trim().toLowerCase() === target)
                ?? (all || []).find(s => String(s.name).trim().toLowerCase().includes(target))
                ?? (all || []).find(s => target.includes(String(s.name).trim().toLowerCase()));

    if (!match) {
      const available = (all || []).map(s => `"${s.name}"`).join(', ') || '(aucun script trouvé)';
      throw new Error(`Script "${this.scriptName}" introuvable.\nScripts disponibles : ${available}`);
    }

    // Cloner tous les paramètres du script de référence qui fonctionne
    const ref = await this.getReferenceScript();
    if (Object.keys(ref).length > 0) {
      const update: Record<string, unknown> = { scriptid: match.scriptid, scope: 2 };
      // Copie les champs d'exécution depuis le script de référence
      for (const key of ['type', 'execute_on', 'groupid', 'host_access', 'usrgrpid', 'confirmation']) {
        if (ref[key] !== undefined) update[key] = ref[key];
      }
      await this.rpc('script.update', update);
    }

    return String(match.scriptid);
  }

  async getHostId(hostname: string): Promise<string | null> {
    const hosts = await this.rpc('host.get', {
      filter: { host: [hostname] },
      output: ['hostid'],
    }) as Array<{ hostid: string }>;
    return hosts && hosts.length > 0 ? hosts[0].hostid : null;
  }

  // Pose la macro {$REAP3R_TOKEN} sur un hôte (crée ou met à jour)
  async setHostToken(hostId: string, token: string): Promise<void> {
    const existing = await this.rpc('usermacro.get', {
      hostids: [hostId],
      filter: { macro: '{$REAP3R_TOKEN}' },
      output: ['hostmacroid'],
    }) as Array<{ hostmacroid: string }>;
    if (existing.length > 0) {
      await this.rpc('usermacro.update', { hostmacroid: existing[0].hostmacroid, value: token });
    } else {
      await this.rpc('usermacro.create', { hostid: hostId, macro: '{$REAP3R_TOKEN}', value: token });
    }
  }

  async executeScript(scriptId: string, hostId: string): Promise<{ ok: boolean; value: string }> {
    const res = await this.rpc('script.execute', {
      scriptid: scriptId, hostid: hostId,
    }) as { response: string; value?: string };
    return { ok: res.response === 'success', value: res.value ?? '' };
  }

  // Crée le script dans Zabbix. Token injecté via macro {$REAP3R_TOKEN}.
  // Compatible Zabbix 5.x et 6.x — aucun paramètre manualinput.
  async createEnrollScript(name: string, serverUrl: string): Promise<string> {
    const server = serverUrl.replace(/\/+$/, '');
    const command = [
      '#!/bin/bash',
      'set -e',
      `SERVER='${server}'`,
      "TOKEN='{$REAP3R_TOKEN}'",
      'if [ -z "$TOKEN" ] || [ "$TOKEN" = "{$REAP3R_TOKEN}" ]; then',
      '  echo "ERREUR: macro {$REAP3R_TOKEN} non definie sur cet hote"; exit 1',
      'fi',
      '',
      'INSTALL_DIR="/opt/reap3r"',
      'AGENT="$INSTALL_DIR/reap3r-agent"',
      '',
      '# Détection architecture',
      'ARCH=$(uname -m)',
      'case "$ARCH" in',
      '  x86_64|amd64) ARCH_PARAM="x86_64" ;;',
      '  aarch64|arm64) ARCH_PARAM="aarch64" ;;',
      '  *) echo "Architecture non supportée: $ARCH"; exit 1 ;;',
      'esac',
      '',
      '# Téléchargement du binaire depuis le serveur Massvision',
      'echo "[1/4] Téléchargement de reap3r-agent depuis $SERVER..."',
      'mkdir -p "$INSTALL_DIR"',
      'curl -fsSL "${SERVER}/api/agent-binary/download?os=linux&arch=${ARCH_PARAM}" -o "$AGENT" || {',
      '  wget -q "${SERVER}/api/agent-binary/download?os=linux&arch=${ARCH_PARAM}" -O "$AGENT"',
      '}',
      'chmod +x "$AGENT"',
      'echo "[2/4] Binaire installé dans $AGENT"',
      '',
      '# Enrôlement',
      'echo "[3/4] Enrôlement auprès de $SERVER..."',
      '"$AGENT" --enroll --server "$SERVER" --token "$TOKEN" 2>&1',
      '',
      '# Service systemd (si disponible)',
      'if command -v systemctl >/dev/null 2>&1; then',
      '  echo "[4/4] Installation du service systemd..."',
      '  cat > /etc/systemd/system/reap3r-agent.service << \'SVCEOF\'',
      '[Unit]',
      'Description=Massvision Reap3r Agent',
      'After=network-online.target',
      'Wants=network-online.target',
      '',
      '[Service]',
      'ExecStart=/opt/reap3r/reap3r-agent --run',
      'Restart=always',
      'RestartSec=15',
      'StandardOutput=journal',
      'StandardError=journal',
      '',
      '[Install]',
      'WantedBy=multi-user.target',
      'SVCEOF',
      '  systemctl daemon-reload',
      '  systemctl enable --now reap3r-agent 2>&1',
      '  echo "Service reap3r-agent démarré."',
      'else',
      '  echo "[4/4] systemd absent, démarrage direct..."',
      '  nohup "$AGENT" --run > /var/log/reap3r-agent.log 2>&1 &',
      '  echo "Agent démarré en arrière-plan (PID $!)"',
      'fi',
      '',
      'echo "✅ Déploiement terminé sur $(hostname)"',
    ].join('\n');

    // Clone tous les paramètres d'exécution du script de référence qui fonctionne
    const ref = await this.getReferenceScript();
    const createParams: Record<string, unknown> = {
      name,
      command,
      scope: 2, // Manual host action
    };
    for (const key of ['type', 'execute_on', 'groupid', 'host_access', 'usrgrpid']) {
      if (ref[key] !== undefined) createParams[key] = ref[key];
    }

    const result = await this.rpc('script.create', createParams) as { scriptids: string[] };

    if (!result?.scriptids?.[0]) throw new Error('Zabbix n\'a pas retourné d\'ID pour le script créé');
    return result.scriptids[0];
  }
}

// ═══════════════════════════════════════════
// CSV/XLSX PARSER
// ═══════════════════════════════════════════
const DAT_RE = /^[a-f0-9]{64}$/i;

function parseFile(content: string | ArrayBuffer, name: string): LocalItem[] {
  const isXlsx = /\.(xlsx|xls)$/i.test(name);
  let rows: string[][] = [];

  if (isXlsx) {
    const wb = XLSX.read(content as ArrayBuffer, { type: 'buffer' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    rows = XLSX.utils.sheet_to_json<string[]>(ws, { header: 1, defval: '' }) as string[][];
  } else {
    const text = content as string;
    rows = text.split(/\r?\n/).filter(l => l.trim()).map(l => {
      const sep = l.includes('\t') ? '\t' : l.includes(';') ? ';' : ',';
      return l.split(sep).map(c => c.trim().replace(/^["']|["']$/g, ''));
    });
  }

  if (rows.length === 0) return [];

  // Detect header row
  const header = rows[0].map(h => h.toLowerCase());
  const hostIdx = header.findIndex(h => ['zabbix_host','host','hostname','server','machine'].includes(h));
  const datIdx  = header.findIndex(h => ['dat','token','key','code','enrollment_token'].includes(h));

  let startRow = 0;
  let hCol: number, dCol: number;

  if (hostIdx !== -1 && datIdx !== -1) {
    // Header found
    hCol = hostIdx; dCol = datIdx; startRow = 1;
  } else {
    // Heuristic: find DAT by format
    const f = rows[0];
    if (f.length >= 2) {
      if (DAT_RE.test(f[0])) { dCol = 0; hCol = 1; }
      else if (DAT_RE.test(f[1])) { hCol = 0; dCol = 1; }
      else { hCol = 0; dCol = 1; }
    } else { hCol = 0; dCol = 1; }
    startRow = 0;
  }

  const items: LocalItem[] = [];
  for (let i = startRow; i < rows.length; i++) {
    const r = rows[i];
    const hostname = (r[hCol] ?? '').trim();
    const dat      = (r[dCol] ?? '').trim();
    if (!hostname || !dat) continue;
    if (!DAT_RE.test(dat)) continue; // skip invalid DATs
    items.push({ id: i, hostname, dat, status: 'pending', message: '' });
  }
  return items;
}

// ═══════════════════════════════════════════
// MAIN PAGE
// ═══════════════════════════════════════════
export default function DeploymentPage() {
  const [activeTab, setActiveTab] = useState<'zabbix' | 'tokens'>('zabbix');

  return (
    <>
      <TopBar title="Deployment" />
      <div className="p-6 space-y-4 animate-fade-in">
        <TabBar
          tabs={[
            { key: 'zabbix' as const, label: 'Zabbix DAT Deploy', icon: <Server style={{ width: '13px', height: '13px' }} /> },
            { key: 'tokens' as const, label: 'Enrollment Tokens', icon: <Key style={{ width: '13px', height: '13px' }} /> },
          ]}
          active={activeTab}
          onChange={setActiveTab}
        />
        {activeTab === 'zabbix' ? <ZabbixDeployTab /> : <EnrollmentTokensTab />}
      </div>
    </>
  );
}

// ═══════════════════════════════════════════
// ZABBIX DEPLOY TAB — FULL BROWSER MODE
// Direct browser → Zabbix (bypasse le firewall VPS)
// ═══════════════════════════════════════════
function ZabbixDeployTab() {
  // Config
  const [zabbixUrl,   setZabbixUrl]   = useState('https://prod-zabbix.hypervision.fr:8081');
  const [zabbixUser,  setZabbixUser]  = useState('massvision');
  const [zabbixPass,  setZabbixPass]  = useState('Chenhao.macross69');
  const [scriptName,  setScriptName]  = useState('Reap3rEnroll');
  const [serverUrl,   setServerUrl]   = useState('https://massvision.pro');

  // Data
  const [items,    setItems]    = useState<LocalItem[]>([]);
  const [filename, setFilename] = useState('');

  // Create script
  const [createState, setCreateState] = useState<'idle' | 'creating' | 'done' | 'error'>('idle');
  const [createMsg,   setCreateMsg]   = useState('');

  // State machine
  const [phase,   setPhase]   = useState<'idle' | 'ready' | 'running' | 'done'>('idle');
  const [logs,    setLogs]    = useState<string[]>([]);
  const [current, setCurrent] = useState(0);
  const abortRef = useRef(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const log = (msg: string) => setLogs(p => {
    const lines = [...p, `[${new Date().toLocaleTimeString()}] ${msg}`];
    return lines.slice(-200); // keep last 200 lines
  });

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // ─── File upload ───
  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    setPhase('idle');
    setItems([]);
    setLogs([]);

    const isXlsx = /\.(xlsx|xls)$/i.test(file.name);
    const reader = new FileReader();
    reader.onload = ev => {
      const result = ev.target?.result;
      if (!result) return;
      const parsed = parseFile(result as string | ArrayBuffer, file.name);
      if (parsed.length === 0) {
        setFilename('');
        alert(`Aucune ligne valide trouvée dans "${file.name}".\nColonnes attendues: zabbix_host (ou host/hostname) + dat (ou token/key)`);
        return;
      }
      setItems(parsed);
      setPhase('ready');
      log(`📂 Fichier chargé: "${file.name}" → ${parsed.length} hôtes valides`);
    };
    if (isXlsx) reader.readAsArrayBuffer(file);
    else reader.readAsText(file);
    // Reset input so same file can be re-selected
    e.target.value = '';
  };

  // ─── Stats ───
  const stats = {
    total:    items.length,
    success:  items.filter(i => i.status === 'success').length,
    failed:   items.filter(i => i.status === 'failed').length,
    skipped:  items.filter(i => i.status === 'skipped').length,
    pending:  items.filter(i => i.status === 'pending').length,
    running:  items.filter(i => i.status === 'running').length,
  };

  // ─── Export CSV ───
  const exportCsv = () => {
    const header = 'hostname,dat,status,message';
    const rows = items.map(i => `${i.hostname},${i.dat},${i.status},"${i.message.replace(/"/g, '""')}"`);
    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `deploy-result-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  // ─── Reset ───
  const reset = () => {
    setPhase('idle');
    setItems([]);
    setFilename('');
    setLogs([]);
    setCurrent(0);
  };

  // ─── DEPLOY ───
  const startDeploy = async () => {
    if (items.length === 0 || phase === 'running') return;
    abortRef.current = false;
    setPhase('running');
    setCurrent(0);
    setLogs([]);

    log(`🚀 Démarrage — ${items.length} hôtes à déployer`);
    log(`🔗 Connexion à ${zabbixUrl}...`);

    const client = new ZabbixBrowserClient(zabbixUrl, scriptName);

    try {
      await client.login(zabbixUser, zabbixPass);
      log(`✅ Authentification réussie`);

      log(`🔍 Recherche du script "${scriptName}"...`);
      let scriptId: string;
      try {
        scriptId = await client.getScriptId();
        log(`✅ Script trouvé — paramètres synchronisés depuis "massvision v5"`);
      } catch {
        log(`⚠️  Script "${scriptName}" introuvable — création automatique dans Zabbix...`);
        try {
          scriptId = await client.createEnrollScript(scriptName, serverUrl);
          log(`✅ Script "${scriptName}" créé automatiquement (ID: ${scriptId})`);
        } catch (createErr: any) {
          throw new Error(`Script introuvable et création impossible : ${createErr.message}`);
        }
      }

      let successCount = 0;
      let failCount = 0;
      let skipCount = 0;

      // Patterns indiquant que l'agent est simplement inaccessible (pas une erreur de script)
      const UNREACHABLE = [
        'cannot connect', 'connection refused', 'timed out', 'interrupted system call',
        'no route to host', 'network unreachable', 'host unreachable', 'connection reset',
      ];

      for (let i = 0; i < items.length; i++) {
        if (abortRef.current) { log('🛑 Déploiement annulé'); break; }

        const item = items[i];
        if (item.status === 'success') { log(`⏩ ${item.hostname} — déjà réussi, ignoré`); continue; }

        setCurrent(i);
        setItems(prev => prev.map((x, idx) => idx === i ? { ...x, status: 'running', message: '' } : x));
        log(`▶️  [${i + 1}/${items.length}] ${item.hostname}...`);

        try {
          const hostId = await client.getHostId(item.hostname);
          if (!hostId) throw new Error('Hôte introuvable dans Zabbix');

          // Injecter le token DAT comme macro {$REAP3R_TOKEN} sur l'hôte
          await client.setHostToken(hostId, item.dat);

          const res = await client.executeScript(scriptId, hostId);

          if (res.ok) {
            setItems(prev => prev.map((x, idx) => idx === i ? { ...x, status: 'success', message: res.value } : x));
            log(`✅ ${item.hostname} — Succès`);
            successCount++;
          } else {
            setItems(prev => prev.map((x, idx) => idx === i ? { ...x, status: 'failed', message: res.value || 'Script retourné en échec' } : x));
            log(`❌ ${item.hostname} — Échec: ${res.value}`);
            failCount++;
          }
        } catch (err: any) {
          const msg: string = err.message || '';
          const isUnreachable = UNREACHABLE.some(p => msg.toLowerCase().includes(p));
          if (isUnreachable) {
            setItems(prev => prev.map((x, idx) => idx === i ? { ...x, status: 'skipped', message: 'Agent inaccessible: ' + msg } : x));
            log(`⚠️  ${item.hostname} — Agent inaccessible (hors ligne / firewall)`);
            skipCount++;
          } else {
            setItems(prev => prev.map((x, idx) => idx === i ? { ...x, status: 'failed', message: msg } : x));
            log(`❌ ${item.hostname} — Erreur: ${msg}`);
            failCount++;
          }
        }

        // Small pause to avoid API rate limiting
        await new Promise(r => setTimeout(r, 150));
      }

      log(`\n🏁 Déploiement terminé — ✅ ${successCount} succès, ❌ ${failCount} échecs, ⚠️ ${skipCount} inaccessibles`);
      setPhase('done');

    } catch (err: any) {
      log(`\n💥 ERREUR FATALE: ${err.message}`);
      log('→ Vérifiez que votre navigateur a accès à Zabbix (pas VPN bloqué, pas CORS)');
      setPhase('done');
    }
  };

  return (
    <div className="space-y-4">

      {/* ── Info Banner ── */}
      <div className="flex items-start gap-3 px-4 py-3 bg-blue-500/10 border border-blue-500/20 rounded-xl">
        <Wifi className="text-blue-400 mt-0.5 shrink-0" style={{ width: '14px', height: '14px' }} />
        <p className="text-[11px] text-blue-300">
          <strong>Mode Navigateur actif</strong> — Le déploiement s&apos;exécute directement depuis votre navigateur vers Zabbix.
          Votre navigateur doit avoir accès à <code className="font-mono">{zabbixUrl}</code>.
        </p>
      </div>

      {/* ── Config Card ── */}
      <Card>
        <h3 className="text-[11px] font-bold text-white uppercase tracking-[0.08em] mb-3">
          Configuration Zabbix
        </h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2 md:col-span-1 space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">URL Zabbix</label>
            <input value={zabbixUrl} onChange={e => setZabbixUrl(e.target.value)}
              disabled={phase === 'running'}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20 disabled:opacity-50" />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Nom du Script</label>
            <input value={scriptName} onChange={e => setScriptName(e.target.value)}
              disabled={phase === 'running'}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20 disabled:opacity-50" />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Utilisateur Zabbix</label>
            <input value={zabbixUser} onChange={e => setZabbixUser(e.target.value)}
              disabled={phase === 'running'}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20 disabled:opacity-50" />
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">Mot de passe / Token API</label>
            <input type="password" value={zabbixPass} onChange={e => setZabbixPass(e.target.value)}
              disabled={phase === 'running'}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20 disabled:opacity-50" />
          </div>
          <div className="col-span-2 space-y-1">
            <label className="block text-[10px] font-bold text-reap3r-muted uppercase tracking-[0.12em]">URL Serveur Reap3r (pour le callback)</label>
            <input value={serverUrl} onChange={e => setServerUrl(e.target.value)}
              disabled={phase === 'running'}
              className="w-full px-3 py-2 bg-reap3r-surface border border-reap3r-border rounded-lg text-[11px] text-white focus:outline-none focus:ring-1 focus:ring-white/20 disabled:opacity-50" />
          </div>
        </div>

        {/* ── Créer le script dans Zabbix ── */}
        <div className="mt-4 pt-4 border-t border-reap3r-border/40 flex items-center gap-3 flex-wrap">
          <Button
            variant="secondary"
            size="sm"
            disabled={phase === 'running' || createState === 'creating'}
            onClick={async () => {
              setCreateState('creating');
              setCreateMsg('');
              try {
                const client = new ZabbixBrowserClient(zabbixUrl, scriptName);
                await client.login(zabbixUser, zabbixPass);
                const id = await client.createEnrollScript(scriptName, serverUrl);
                setCreateState('done');
                setCreateMsg(`✅ Script "${scriptName}" créé dans Zabbix (ID: ${id}). Vous pouvez maintenant lancer le déploiement.`);
              } catch (err: any) {
                setCreateState('error');
                setCreateMsg(`❌ ${err.message}`);
              }
            }}
          >
            {createState === 'creating'
              ? <><RotateCcw className="animate-spin" style={{ width: '11px', height: '11px', marginRight: '5px' }} />Création en cours...</>
              : <><Plus style={{ width: '11px', height: '11px', marginRight: '5px' }} />Créer le script &quot;{scriptName}&quot; dans Zabbix</>
            }
          </Button>
          {createMsg && (
            <span className={`text-[11px] ${createState === 'done' ? 'text-green-400' : 'text-red-400'}`}>
              {createMsg}
            </span>
          )}
        </div>
      </Card>

      {/* ── Upload + Actions ── */}
      <div className="flex flex-wrap items-center gap-3">
        {/* File picker */}
        <label className={`flex items-center gap-2 px-4 py-2.5 border-2 border-dashed rounded-xl cursor-pointer transition-all text-[11px]
          ${phase === 'running' ? 'opacity-40 pointer-events-none' : 'border-reap3r-border hover:border-white/30 text-reap3r-muted hover:text-white'}`}>
          <Upload style={{ width: '13px', height: '13px' }} />
          {filename ? <><FileSpreadsheet style={{ width: '13px', height: '13px' }} className="text-reap3r-accent" />{filename}</> : 'Charger CSV / XLSX'}
          <input type="file" accept=".csv,.txt,.tsv,.xlsx,.xls" onChange={onFile} className="hidden" disabled={phase === 'running'} />
        </label>

        {/* Deploy button */}
        {phase !== 'idle' && (
          <>
            <Button
              onClick={startDeploy}
              disabled={phase === 'running' || items.length === 0}
              variant="primary"
            >
              {phase === 'running'
                ? <><RotateCcw className="animate-spin" style={{ width: '12px', height: '12px', marginRight: '6px' }} />Déploiement en cours...</>
                : <><Play style={{ width: '12px', height: '12px', marginRight: '6px' }} />{phase === 'done' ? 'Relancer' : 'Déployer'} ({items.filter(i => i.status !== 'success').length} hôtes)</>
              }
            </Button>

            {phase === 'running' && (
              <Button variant="danger" size="sm" onClick={() => { abortRef.current = true; }}>
                <XCircle style={{ width: '12px', height: '12px', marginRight: '4px' }} />Arrêter
              </Button>
            )}

            {phase === 'done' && (
              <>
                <Button variant="secondary" size="sm" onClick={exportCsv}>
                  <Download style={{ width: '12px', height: '12px', marginRight: '4px' }} />Exporter résultats
                </Button>
                <Button variant="ghost" size="sm" onClick={reset}>
                  <RotateCcw style={{ width: '12px', height: '12px', marginRight: '4px' }} />Nouveau déploiement
                </Button>
              </>
            )}
          </>
        )}
      </div>

      {/* ── Stats ── */}
      {items.length > 0 && (
        <div className="grid grid-cols-6 gap-2">
          {[
            { label: 'Total',        value: stats.total,   color: 'text-white' },
            { label: 'En cours',     value: stats.running, color: 'text-yellow-400' },
            { label: 'Succès',       value: stats.success, color: 'text-green-400' },
            { label: 'Échecs',       value: stats.failed,  color: 'text-red-400' },
            { label: 'Inaccessible', value: stats.skipped, color: 'text-orange-400' },
            { label: 'Attente',      value: stats.pending, color: 'text-reap3r-muted' },
          ].map(s => (
            <div key={s.label} className="flex flex-col items-center p-2.5 bg-reap3r-surface/40 border border-reap3r-border/40 rounded-xl">
              <span className={`text-[18px] font-bold ${s.color}`}>{s.value}</span>
              <span className="text-[9px] text-reap3r-muted uppercase tracking-wider mt-0.5">{s.label}</span>
            </div>
          ))}
        </div>
      )}

      {/* ── Items Table ── */}
      {items.length > 0 && (
        <Card className="overflow-hidden p-0">
          <div className="max-h-[400px] overflow-y-auto">
            <table className="w-full text-[11px]">
              <thead className="sticky top-0 bg-reap3r-bg border-b border-reap3r-border/40 z-10">
                <tr className="text-left text-reap3r-muted uppercase tracking-wider">
                  <th className="px-4 py-2.5 font-semibold">#</th>
                  <th className="px-4 py-2.5 font-semibold">Hôte Zabbix</th>
                  <th className="px-4 py-2.5 font-semibold">Token (extrait)</th>
                  <th className="px-4 py-2.5 font-semibold">Statut</th>
                  <th className="px-4 py-2.5 font-semibold">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-reap3r-border/20">
                {items.map((item, idx) => (
                  <tr key={item.id}
                    className={`transition-colors ${item.status === 'running' ? 'bg-yellow-500/5' : item.status === 'success' ? 'bg-green-500/5' : item.status === 'failed' ? 'bg-red-500/5' : 'hover:bg-white/3'}`}>
                    <td className="px-4 py-2 text-reap3r-muted font-mono">{idx + 1}</td>
                    <td className="px-4 py-2 text-white font-mono font-medium">{item.hostname}</td>
                    <td className="px-4 py-2 text-reap3r-muted font-mono text-[10px]">{item.dat.substring(0, 8)}…</td>
                    <td className="px-4 py-2"><StatusBadge s={item.status} /></td>
                    <td className="px-4 py-2 text-reap3r-muted max-w-[260px] truncate text-[10px]" title={item.message}>{item.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ── Logs terminal ── */}
      {logs.length > 0 && (
        <Card className="p-0 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-reap3r-border/40 bg-reap3r-surface/60">
            <span className="text-[10px] font-bold text-reap3r-muted uppercase tracking-wider flex items-center gap-2">
              <Activity style={{ width: '11px', height: '11px' }} />Journal d&apos;exécution
            </span>
            <button onClick={() => setLogs([])} className="text-[10px] text-reap3r-muted hover:text-white transition-colors">Effacer</button>
          </div>
          <div className="h-[180px] overflow-y-auto bg-black/40 p-3 font-mono text-[10px] space-y-0.5">
            {logs.map((l, i) => (
              <div key={i} className={`${l.includes('❌') || l.includes('💥') ? 'text-red-400' : l.includes('✅') || l.includes('🏁') ? 'text-green-400' : l.includes('⏩') ? 'text-reap3r-muted' : 'text-white/70'}`}>
                {l}
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </Card>
      )}

      {/* ── Empty state ── */}
      {phase === 'idle' && (
        <Card>
          <EmptyState
            icon={<FileSpreadsheet style={{ width: '28px', height: '28px' }} />}
            title="Charger un fichier CSV ou XLSX"
            description="Colonnes requises : zabbix_host (ou host/hostname) + dat (ou token/key). Format accepté : virgule, point-virgule, tabulation."
          />
        </Card>
      )}
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
