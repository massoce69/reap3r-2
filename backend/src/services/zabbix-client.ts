// ─────────────────────────────────────────────
// MASSVISION Reap3r — Zabbix API Client
// JSON-RPC 2.0 client for Zabbix 6.x / 7.x
// ─────────────────────────────────────────────

interface ZabbixConfig {
  url: string;        // e.g. https://zabbix.company.com/api_jsonrpc.php
  user: string;
  password: string;
  timeout?: number;   // ms, default 15000
}

function parseEndpoint(inputUrl: string): { host: string; port: string; protocol: string } {
  try {
    const u = new URL(inputUrl);
    return {
      host: u.hostname,
      port: u.port || (u.protocol === 'https:' ? '443' : '80'),
      protocol: u.protocol,
    };
  } catch {
    return { host: 'unknown-host', port: 'unknown-port', protocol: 'unknown:' };
  }
}

export interface ZabbixHost {
  hostid: string;
  host: string;
  name: string;
  status: string;
}

export interface ZabbixScript {
  scriptid: string;
  name: string;
  type: string;
}

interface ZabbixHostMacro {
  hostmacroid: string;
  macro: string;
  value?: string;
}

interface ZabbixHostInterface {
  interfaceid: string;
  type: string;
  main: string;
  port: string;
  ip?: string;
  dns?: string;
}

interface ZabbixScriptExecResult {
  response: string;   // 'success' | 'failed'
  value?: string;
  debug?: string[];
}

export interface ZabbixExactResolveResult<T> {
  state: 'ok' | 'not_found' | 'ambiguous';
  entity?: T;
  matches?: T[];
}

// ── Circuit Breaker ──
interface CircuitBreakerState {
  failures: number;
  total: number;
  windowStart: number;
  open: boolean;
  openUntil: number;
}

const CIRCUIT_WINDOW_MS = 2 * 60 * 1000;    // 2 minutes
const CIRCUIT_THRESHOLD = 0.30;               // 30% failure rate
const CIRCUIT_MIN_CALLS = 5;                  // Minimum calls before tripping
const CIRCUIT_COOLDOWN_MS = 60 * 1000;        // 1 minute cooldown

export class ZabbixClient {
  private url: string;
  private endpoint: { host: string; port: string; protocol: string };
  private user: string;
  private password: string;
  private timeout: number;
  private authToken: string | null = null;
  private tokenExpiresAt = 0;
  private requestId = 1;

  // Circuit breaker
  private circuit: CircuitBreakerState = {
    failures: 0,
    total: 0,
    windowStart: Date.now(),
    open: false,
    openUntil: 0,
  };

  constructor(cfg: ZabbixConfig) {
    // Ensure URL ends with /api_jsonrpc.php
    this.url = cfg.url.replace(/\/?$/, '').replace(/\/api_jsonrpc\.php$/, '') + '/api_jsonrpc.php';
    this.endpoint = parseEndpoint(this.url);
    this.user = cfg.user;
    this.password = cfg.password;
    this.timeout = cfg.timeout ?? 15_000;
    
    // Support static API token if provided via password (heuristic) OR external config
    // If password is exactly 64 hex chars, treat as API token
    if (/^[a-f0-9]{64}$/i.test(this.password)) {
      this.authToken = this.password;
      this.tokenExpiresAt = Number.MAX_SAFE_INTEGER; // Never expires
    }
  }

  // ════════════════════════════════════════
  // CIRCUIT BREAKER
  // ════════════════════════════════════════

  private checkCircuit(): void {
    if (this.circuit.open) {
      if (Date.now() < this.circuit.openUntil) {
        throw new ZabbixCircuitOpenError(
          `Zabbix circuit breaker OPEN until ${new Date(this.circuit.openUntil).toISOString()}`
        );
      }
      // Half-open: allow one request
      this.circuit.open = false;
      this.resetCircuitWindow();
    }
  }

  private recordSuccess(): void {
    this.circuit.total++;
    this.maybeResetWindow();
  }

  private recordFailure(): void {
    this.circuit.failures++;
    this.circuit.total++;
    this.maybeResetWindow();

    if (this.circuit.total >= CIRCUIT_MIN_CALLS) {
      const rate = this.circuit.failures / this.circuit.total;
      if (rate >= CIRCUIT_THRESHOLD) {
        this.circuit.open = true;
        this.circuit.openUntil = Date.now() + CIRCUIT_COOLDOWN_MS;
        console.error(`[zabbix-client] Circuit breaker OPEN — ${(rate * 100).toFixed(1)}% failure rate (${this.circuit.failures}/${this.circuit.total})`);
      }
    }
  }

  private maybeResetWindow(): void {
    if (Date.now() - this.circuit.windowStart > CIRCUIT_WINDOW_MS) {
      this.resetCircuitWindow();
    }
  }

  private resetCircuitWindow(): void {
    this.circuit.failures = 0;
    this.circuit.total = 0;
    this.circuit.windowStart = Date.now();
  }

  get isCircuitOpen(): boolean {
    return this.circuit.open && Date.now() < this.circuit.openUntil;
  }

  // ════════════════════════════════════════
  // JSON-RPC TRANSPORT
  // ════════════════════════════════════════

  private async rpc<T>(method: string, params: Record<string, unknown>, auth = true): Promise<T> {
    this.checkCircuit();

    const body = {
      jsonrpc: '2.0',
      method,
      params,
      id: this.requestId++,
      ...(auth && this.authToken ? { auth: this.authToken } : {}),
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json-rpc' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new ZabbixApiError(`HTTP ${res.status}: ${res.statusText}`, method, true);
      }

      const json = await res.json() as { result?: T; error?: { code: number; message: string; data: string } };
      if (json.error) {
        const retryable = isRetryableZabbixError(json.error.code);
        throw new ZabbixApiError(
          `${json.error.message}: ${json.error.data}`,
          method,
          retryable,
        );
      }

      this.recordSuccess();
      return json.result as T;
    } catch (err: any) {
      if (err instanceof ZabbixCircuitOpenError) throw err;
      if (err.name === 'AbortError') {
        this.recordFailure();
        throw new ZabbixApiError(
          `Request timeout (${this.endpoint.host}:${this.endpoint.port})`,
          method,
          true,
        );
      }
      if (err instanceof ZabbixApiError) {
        if (err.retryable) this.recordFailure();
        throw err;
      }
      // Network error
      this.recordFailure();
      const detailed = (err.cause as any)?.code || (err.cause as any)?.message || err.message;
      const isConnectTimeout = String(detailed).includes('UND_ERR_CONNECT_TIMEOUT');
      if (isConnectTimeout) {
        throw new ZabbixApiError(
          `Network error: cannot reach Zabbix endpoint ${this.endpoint.host}:${this.endpoint.port} from backend (${detailed})`,
          method,
          true,
        );
      }
      throw new ZabbixApiError(
        `Network error (${this.endpoint.host}:${this.endpoint.port}): ${detailed}`,
        method,
        true,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  // ════════════════════════════════════════
  // AUTH
  // ════════════════════════════════════════

  async login(): Promise<string> {
    // Zabbix 7.x uses user.login, same as 6.x
    const token = await this.rpc<string>('user.login', {
      user: this.user,       // Zabbix 6.x param name
      username: this.user,   // Zabbix 7.x param name (both sent for compat)
      password: this.password,
    }, false);

    this.authToken = token;
    this.tokenExpiresAt = Date.now() + 25 * 60 * 1000; // Refresh every 25 min (Zabbix default session is 30 min)
    console.log('[zabbix-client] Authenticated successfully');
    return token;
  }

  private async ensureAuth(): Promise<void> {
    if (!this.authToken || Date.now() > this.tokenExpiresAt) {
      await this.login();
    }
  }

  async logout(): Promise<void> {
    if (this.authToken) {
      try { await this.rpc('user.logout', {}); } catch { /* ignore */ }
      this.authToken = null;
    }
  }

  // ════════════════════════════════════════
  // HOST
  // ════════════════════════════════════════

  /**
   * Resolve a single host by exact hostname.
   * Returns null if not found.
   */
  async hostGet(hostname: string): Promise<ZabbixHost | null> {
    await this.ensureAuth();
    const hosts = await this.rpc<ZabbixHost[]>('host.get', {
      filter: { host: [hostname] },
      output: ['hostid', 'host', 'name', 'status'],
      limit: 1,
    });
    return hosts.length > 0 ? hosts[0] : null;
  }

  /**
   * Resolve multiple hosts by hostnames (batch).
   * Returns a map hostname → ZabbixHost.
   */
  async hostGetBatch(hostnames: string[]): Promise<Map<string, ZabbixHost>> {
    await this.ensureAuth();
    const map = new Map<string, ZabbixHost>();
    if (hostnames.length === 0) return map;

    // Zabbix supports batch filter
    const hosts = await this.rpc<ZabbixHost[]>('host.get', {
      filter: { host: hostnames },
      output: ['hostid', 'host', 'name', 'status'],
    });

    for (const h of hosts) {
      map.set(h.host, h);
    }
    return map;
  }

  /**
   * Resolve hostnames with exact match semantics and ambiguity detection.
   * - 1 exact match on host -> ok
   * - 0 on host, then exact name lookup:
   *   - 1 exact name match -> ok
   *   - >1 -> ambiguous
   *   - 0 -> not_found
   */
  async hostResolveBatchExact(hostnames: string[]): Promise<Map<string, ZabbixExactResolveResult<ZabbixHost>>> {
    await this.ensureAuth();
    const uniq = Array.from(new Set(hostnames.map((h) => h.trim()).filter(Boolean)));
    const out = new Map<string, ZabbixExactResolveResult<ZabbixHost>>();
    if (uniq.length === 0) return out;

    const byHost = await this.rpc<ZabbixHost[]>('host.get', {
      filter: { host: uniq },
      output: ['hostid', 'host', 'name', 'status'],
    });

    const hostIdx = new Map<string, ZabbixHost[]>();
    for (const h of byHost) {
      const k = h.host;
      const list = hostIdx.get(k) ?? [];
      list.push(h);
      hostIdx.set(k, list);
    }

    const unresolved: string[] = [];
    for (const wanted of uniq) {
      const matches = hostIdx.get(wanted) ?? [];
      if (matches.length === 1) {
        out.set(wanted, { state: 'ok', entity: matches[0], matches });
      } else if (matches.length > 1) {
        out.set(wanted, { state: 'ambiguous', matches });
      } else {
        unresolved.push(wanted);
      }
    }

    if (unresolved.length > 0) {
      const byName = await this.rpc<ZabbixHost[]>('host.get', {
        filter: { name: unresolved },
        output: ['hostid', 'host', 'name', 'status'],
      });

      const nameIdx = new Map<string, ZabbixHost[]>();
      for (const h of byName) {
        const k = h.name;
        const list = nameIdx.get(k) ?? [];
        list.push(h);
        nameIdx.set(k, list);
      }

      for (const wanted of unresolved) {
        const matches = nameIdx.get(wanted) ?? [];
        if (matches.length === 1) {
          out.set(wanted, { state: 'ok', entity: matches[0], matches });
        } else if (matches.length > 1) {
          out.set(wanted, { state: 'ambiguous', matches });
        } else {
          out.set(wanted, { state: 'not_found', matches: [] });
        }
      }
    }

    return out;
  }

  async hostInterfaces(hostId: string): Promise<ZabbixHostInterface[]> {
    await this.ensureAuth();
    return this.rpc<ZabbixHostInterface[]>('hostinterface.get', {
      hostids: [hostId],
      output: ['interfaceid', 'type', 'main', 'port', 'ip', 'dns'],
    });
  }

  /**
   * Zabbix passive agent default is 10050.
   * Some environments accidentally set 10051 (server/trapper port) on host interface,
   * which breaks script.execute on "execute on agent".
   * When aggressive=true, also forces macro-based interface ports to 10050.
   * Returns number of effective fixes applied.
   */
  async normalizeAgentInterfacePort(hostId: string, aggressive = false): Promise<number> {
    const ifaces = await this.hostInterfaces(hostId);
    const agentIfaces = ifaces.filter((i) => Number(i.type) === 1);
    let updated = 0;

    for (const iface of agentIfaces) {
      const portRaw = String(iface.port ?? '').trim();
      if (portRaw === '10051') {
        await this.rpc('hostinterface.update', {
          interfaceid: iface.interfaceid,
          port: '10050',
        });
        updated++;
        continue;
      }

      const macroMatch = portRaw.match(/^\{\$[A-Z0-9_.]+\}$/i);
      if (!aggressive || !macroMatch) continue;

      const macro = macroMatch[0];
      const existing = await this.rpc<ZabbixHostMacro[]>('usermacro.get', {
        hostids: [hostId],
        filter: { macro: [macro] },
        output: ['hostmacroid', 'macro', 'value'],
        limit: 1,
      });
      const current = (existing[0]?.value ?? '').trim();
      if (current === '10050') continue;
      await this.upsertHostMacro(hostId, macro, '10050');
      updated++;
    }
    return updated;
  }

  // ════════════════════════════════════════
  // SCRIPT
  // ════════════════════════════════════════

  /**
   * Upsert one user macro on a host.
   */
  async upsertHostMacro(hostId: string, macro: string, value: string): Promise<void> {
    await this.ensureAuth();

    const existing = await this.rpc<ZabbixHostMacro[]>('usermacro.get', {
      hostids: [hostId],
      filter: { macro: [macro] },
      output: ['hostmacroid', 'macro'],
      limit: 1,
    });

    if (existing.length > 0) {
      await this.rpc('usermacro.update', {
        hostmacroid: existing[0].hostmacroid,
        value,
      });
      return;
    }

    await this.rpc('usermacro.create', {
      hostid: hostId,
      macro,
      value,
    });
  }

  /**
   * Upsert many host macros.
   */
  async upsertHostMacros(hostId: string, macros: Record<string, string>): Promise<void> {
    for (const [macro, value] of Object.entries(macros)) {
      if (!macro) continue;
      await this.upsertHostMacro(hostId, macro, value ?? '');
    }
  }

  /**
   * Find a Zabbix global script by name.
   */
  async scriptGet(name: string): Promise<ZabbixScript | null> {
    await this.ensureAuth();
    const scripts = await this.rpc<ZabbixScript[]>('script.get', {
      filter: { name: [name] },
      output: ['scriptid', 'name', 'type'],
      limit: 1,
    });
    return scripts.length > 0 ? scripts[0] : null;
  }

  async scriptResolveExact(name: string): Promise<ZabbixExactResolveResult<ZabbixScript>> {
    await this.ensureAuth();
    const scripts = await this.rpc<ZabbixScript[]>('script.get', {
      filter: { name: [name] },
      output: ['scriptid', 'name', 'type'],
    });

    const exact = scripts.filter((s) => s.name === name);
    if (exact.length === 1) return { state: 'ok', entity: exact[0], matches: exact };
    if (exact.length > 1) return { state: 'ambiguous', matches: exact };
    return { state: 'not_found', matches: [] };
  }

  /**
   * Execute a Zabbix global script on a host.
   * ONLY call this in LIVE mode — dry_run must NEVER call this.
   */
  async scriptExecute(scriptId: string, hostId: string, macros?: Record<string, string>): Promise<ZabbixScriptExecResult> {
    await this.ensureAuth();
    const params: Record<string, unknown> = {
      scriptid: scriptId,
      hostid: hostId,
    };
    if (macros) {
      // Zabbix 7.x supports manualinput; for macros, pass as user macros
      params.manualinput = Object.entries(macros).map(([macro, value]) => `${macro}=${value}`).join('\n');
    }
    return this.rpc<ZabbixScriptExecResult>('script.execute', params);
  }
}

// ═══════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════

export class ZabbixApiError extends Error {
  constructor(
    message: string,
    public readonly method: string,
    public readonly retryable: boolean,
  ) {
    super(message);
    this.name = 'ZabbixApiError';
  }
}

export class ZabbixCircuitOpenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZabbixCircuitOpenError';
  }
}

function isRetryableZabbixError(code: number): boolean {
  // Zabbix error codes that warrant retry:
  // -32600 (invalid request), -32602 (invalid params) → non-retryable
  // -32603 (internal error) → retryable
  // -32300 (transport error) → retryable
  return code === -32603 || code === -32300;
}
