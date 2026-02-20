
'use client';

import { useState, useCallback, useRef } from 'react';
import { Card, Button, Badge } from '@/components/ui';
import { Download, Upload, Play, RotateCcw, XCircle, CheckCircle2, AlertTriangle, Monitor, FileSpreadsheet, Server, Eye } from 'lucide-react';
import Papa from 'papaparse';
import * as XLSX from 'xlsx';

// ----------------------------------------------------------------------------
// ZABBIX API CLIENT (Running in Browser)
// ----------------------------------------------------------------------------

interface ZabbixConfig {
  url: string;
  user: string;
  password?: string;
  token?: string;
  script?: string;
}

export class BrowserZabbixClient {
  private url: string;
  private token: string | null = null;
  private scriptName: string;

  constructor(cfg: ZabbixConfig) {
    this.url = cfg.url.replace(/\/api_jsonrpc\.php$/, '') + '/api_jsonrpc.php';
    this.scriptName = cfg.script || 'Reap3rEnroll';
    if (cfg.token) {
        this.token = cfg.token;
    } else if (cfg.password && /^[a-f0-9]{64}$/i.test(cfg.password)) {
        this.token = cfg.password;
    }
  }

  async rpc(method: string, params: any) {
    const body: {
      jsonrpc: string;
      method: string;
      params: any;
      id: number;
      auth?: string | null;
    } = {
      jsonrpc: '2.0',
      method,
      params,
      id: Date.now(),
      auth: this.token,
    };

    // If method is user.login, auth should be null
    if (method === 'user.login') delete body.auth;

    const res = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json-rpc' },
      body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    const json = await res.json() as any;
    if (json.error) throw new Error(`Zabbix API Error: ${json.error.message} (${json.error.data})`);
    return json.result;
  }

  async login(user: string, pass: string) {
    // If token already set (static), skip login
    if (this.token) return;
    this.token = await this.rpc('user.login', { user, password: pass });
  }

  async getScriptId() {
    const scripts = await this.rpc('script.get', { filter: { name: this.scriptName }, output: ['scriptid'] });
    if (scripts.length === 0) throw new Error(`Global script "${this.scriptName}" not found`);
    return scripts[0].scriptid;
  }

  async resolveHost(hostname: string) {
    const hosts = await this.rpc('host.get', { filter: { host: [hostname] }, output: ['hostid', 'host'] });
    return hosts.length > 0 ? hosts[0].hostid : null;
  }

  async executeScript(scriptId: string, hostId: string, manualInput: string) {
    return this.rpc('script.execute', { scriptid: scriptId, hostid: hostId, manualinput: manualInput });
  }
}

// ----------------------------------------------------------------------------
// COMPONENT
// ----------------------------------------------------------------------------

interface DeployItem {
  id: string;
  hostname: string;
  token: string;
  status: 'pending' | 'success' | 'failed' | 'skipped' | 'running';
  message: string;
}

export function BrowserDeployTab() {
  const [items, setItems] = useState<DeployItem[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  
  // Conf
  const [zabbixUrl, setZabbixUrl] = useState('https://prod-zabbix.hypervision.fr:8081/');
  const [zabbixUser, setZabbixUser] = useState('massvision');
  const [zabbixPass, setZabbixPass] = useState(''); // User provides this
  const [scriptName, setScriptName] = useState('Reap3rEnroll');
  const [serverUrl, setServerUrl] = useState('https://massvision.pro');
  
  const addLog = (msg: string) => setLogs(p => [...p, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  const formatDeployError = useCallback((message: string) => {
    if (message.includes('UND_ERR_CONNECT_TIMEOUT')) {
      return 'Zabbix unreachable (connect timeout). Check URL/port and firewall from your current network.';
    }
    return message;
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const parseContent = (content: string) => {
      const lines = content.split(/\r?\n/).filter(l => l.trim());
      const newItems: DeployItem[] = [];
      const HEX64 = /^[a-f0-9]{64}$/i;

      lines.forEach((line, idx) => {
        const sep = line.includes(';') ? ';' : line.includes('\t') ? '\t' : ',';
        const cols = line.split(sep).map(c => c.trim().replace(/^["']|["']$/g, ''));
        if (cols.length < 2) return;

        let hostname = '';
        let token = '';

        if (HEX64.test(cols[0])) { token = cols[0]; hostname = cols[1]; }
        else if (HEX64.test(cols[1])) { token = cols[1]; hostname = cols[0]; }
        
        if (token && hostname) {
          newItems.push({
            id: String(idx),
            hostname,
            token,
            status: 'pending',
            message: ''
          });
        }
      });
      setItems(newItems);
      addLog(`Parsed ${newItems.length} valid rows from ${file.name}`);
    };

    const reader = new FileReader();
    reader.onload = (ev) => parseContent(ev.target?.result as string);
    reader.readAsText(file);
  };

  const runDeploy = async () => {
    if (items.length === 0) return alert('No items to deploy');
    if (!zabbixPass) return alert('Zabbix password/token required');
    
    setIsRunning(true);
    addLog('Starting browser-based deployment...');

    try {
      const client = new BrowserZabbixClient({
        url: zabbixUrl,
        user: zabbixUser,
        password: zabbixPass,
        script: scriptName
      });

      addLog('Authenticating...');
      await client.login(zabbixUser, zabbixPass);
      addLog('Authenticated!');

      addLog(`Resolving script "${scriptName}"...`);
      const scriptId = await client.getScriptId();
      addLog(`Script ID: ${scriptId}`);

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.status === 'success') continue;

        setItems(prev => {
           const next = [...prev];
           next[i].status = 'running';
           return next;
        });

        try {
          const hostId = await client.resolveHost(item.hostname);
          if (!hostId) {
             throw new Error('Host not found');
          }

          // Execute
          const manualInput = `${serverUrl} ${item.token}`;
          const res = await client.executeScript(scriptId, hostId, manualInput);

          setItems(prev => {
             const next = [...prev];
             next[i].status = res.response === 'success' ? 'success' : 'failed';
             next[i].message = res.value;
             return next;
          });
          
        } catch (err: any) {
          const message = formatDeployError(String(err?.message ?? 'Unknown error'));
          setItems(prev => {
             const next = [...prev];
             next[i].status = 'failed';
             next[i].message = message;
             return next;
          });
        }
      }
      addLog('Deployment complete.');

    } catch (err: any) {
      const message = formatDeployError(String(err?.message ?? 'Unknown error'));
      addLog(`FATAL ERROR: ${message}`);
      alert(`Deployment stopped: ${message}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card className="p-4 border-l-4 border-l-reap3r-accent bg-reap3r-bg-subtle">
        <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
            <Monitor className="w-4 h-4" /> BROWSER MODE Active
        </h3>
        <p className="text-xs text-reap3r-muted">
            The deployment runs <strong>directly from your browser</strong> to bypass server firewalls.
            Keep this tab open until finished.
        </p>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="space-y-2">
            <label className="text-xs font-semibold text-reap3r-muted">Zabbix URL</label>
            <input className="w-full bg-reap3r-bg-input border border-white/10 rounded px-3 py-2 text-xs" 
                   value={zabbixUrl} onChange={e => setZabbixUrl(e.target.value)} />
        </div>
        <div className="space-y-2">
            <label className="text-xs font-semibold text-reap3r-muted">Username</label>
            <input className="w-full bg-reap3r-bg-input border border-white/10 rounded px-3 py-2 text-xs" 
                   value={zabbixUser} onChange={e => setZabbixUser(e.target.value)} />
        </div>
        <div className="space-y-2">
            <label className="text-xs font-semibold text-reap3r-muted">Password / API Token</label>
            <input type="password" className="w-full bg-reap3r-bg-input border border-white/10 rounded px-3 py-2 text-xs" 
                   value={zabbixPass} onChange={e => setZabbixPass(e.target.value)} placeholder="Enter password..." />
        </div>
      </div>

      <div className="flex gap-4 items-end">
        <div className="flex-1">
             <label className="block text-xs font-semibold text-reap3r-muted mb-2">CSV File (Hostname;Token)</label>
             <input type="file" onChange={handleFileUpload} className="block w-full text-xs text-reap3r-muted file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-xs file:font-semibold file:bg-reap3r-accent file:text-white hover:file:bg-reap3r-accent-dim" />
        </div>
        <Button onClick={runDeploy} disabled={isRunning || items.length === 0} variant={isRunning ? 'secondary' : 'primary'}>
            {isRunning ? <RotateCcw className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            {isRunning ? 'Running...' : 'Start Browser Deploy'}
        </Button>
      </div>

      {/* Results Table */}
      <div className="bg-reap3r-bg-subtle rounded-lg border border-white/5 overflow-hidden">
        <div className="max-h-[400px] overflow-y-auto">
            <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-reap3r-bg border-b border-white/10">
                    <tr>
                        <th className="p-3 font-semibold text-reap3r-muted">Hostname</th>
                        <th className="p-3 font-semibold text-reap3r-muted">Token (Excerpt)</th>
                        <th className="p-3 font-semibold text-reap3r-muted">Status</th>
                        <th className="p-3 font-semibold text-reap3r-muted">Message</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                    {items.map((item) => (
                        <tr key={item.id} className="hover:bg-white/5">
                            <td className="p-3 font-mono">{item.hostname}</td>
                            <td className="p-3 font-mono text-[10px] text-white/50">{item.token.substring(0, 8)}...</td>
                            <td className="p-3">
                                {item.status === 'pending' && <Badge variant="default">Pending</Badge>}
                                {item.status === 'running' && <Badge variant="warning">Running</Badge>}
                                {item.status === 'success' && <Badge variant="success">Success</Badge>}
                                {item.status === 'failed' && <Badge variant="danger">Failed</Badge>}
                            </td>
                            <td className="p-3 text-white/70 truncate max-w-[200px]" title={item.message}>
                                {item.message}
                            </td>
                        </tr>
                    ))}
                    {items.length === 0 && (
                        <tr><td colSpan={4} className="p-8 text-center text-reap3r-muted">No items loaded via CSV yet.</td></tr>
                    )}
                </tbody>
            </table>
        </div>
      </div>

      {/* Logs */}
      <div className="bg-black/30 p-2 rounded text-[10px] font-mono h-[150px] overflow-y-auto border border-white/5">
        {logs.map((l, i) => <div key={i} className="text-white/60">{l}</div>)}
        {logs.length === 0 && <div className="text-white/20 italic">Ready for logs...</div>}
      </div>
    </div>
  );
}
