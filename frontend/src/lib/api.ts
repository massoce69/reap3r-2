// ─────────────────────────────────────────────
// MASSVISION Reap3r — API Client
// ─────────────────────────────────────────────

function getApiBase(): string {
  const fromEnv = process.env.NEXT_PUBLIC_API_URL;
  if (fromEnv && fromEnv.trim()) return fromEnv.replace(/\/+$/, '');

  // In the browser, default to same-origin so Nginx can proxy `/api/*`.
  if (typeof window !== 'undefined') return '';

  // Server-side fallback (mainly for local/dev). In production, prefer setting NEXT_PUBLIC_API_URL.
  return process.env.NODE_ENV === 'development' ? 'http://localhost:4000' : 'http://127.0.0.1:4000';
}

const API_BASE = getApiBase();

export class ApiError extends Error {
  constructor(
    public statusCode: number,
    public error: string,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('reap3r_token');
}

function getRefreshToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('reap3r_refresh_token');
}

export function setToken(token: string, refreshToken?: string) {
  localStorage.setItem('reap3r_token', token);
  if (refreshToken) localStorage.setItem('reap3r_refresh_token', refreshToken);
}

export function clearToken() {
  localStorage.removeItem('reap3r_token');
  localStorage.removeItem('reap3r_refresh_token');
}

let refreshPromise: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  const existingRefreshToken = getRefreshToken();
  if (!existingRefreshToken) return null;
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: existingRefreshToken }),
      });
      if (!res.ok) {
        clearToken();
        return null;
      }
      const body = await res.json().catch(() => ({} as any));
      if (!body?.token || !body?.refresh_token) {
        clearToken();
        return null;
      }
      setToken(body.token, body.refresh_token);
      return body.token as string;
    } catch {
      clearToken();
      return null;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

async function request<T>(path: string, options: RequestInit = {}, allowRefresh = true): Promise<T> {
  const accessToken = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> ?? {}),
  };
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

  // Only set JSON content-type when we actually send a body.
  // Fastify rejects empty bodies when content-type is application/json.
  const hasBody = options.body !== undefined && options.body !== null;
  const isFormData =
    typeof FormData !== 'undefined' && options.body instanceof FormData;
  if (hasBody && !isFormData && !('Content-Type' in headers)) {
    headers['Content-Type'] = 'application/json';
  }

  let res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401 && allowRefresh && path !== '/api/auth/login' && path !== '/api/auth/refresh') {
    const refreshedToken = await refreshAccessToken();
    if (refreshedToken) {
      const retryHeaders: Record<string, string> = { ...headers, Authorization: `Bearer ${refreshedToken}` };
      res = await fetch(`${API_BASE}${path}`, { ...options, headers: retryHeaders });
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      res.status,
      body.error ?? 'Error',
      body.message ?? `Request failed: ${res.status}`
    );
  }

  return res.json();
}

// ── Auth ──
export const api = {
  auth: {
    login: (email: string, password: string, mfa_code?: string) =>
      request<{ token?: string; refresh_token?: string; user?: any; mfa_required?: boolean }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password, ...(mfa_code ? { mfa_code } : {}) }),
      }),
    refresh: (refresh_token?: string) =>
      request<{ token: string; refresh_token: string; user?: any }>(
        '/api/auth/refresh',
        {
          method: 'POST',
          body: JSON.stringify({ refresh_token: refresh_token ?? getRefreshToken() }),
        },
        false,
      ),
    logout: () =>
      request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
    logoutAll: () =>
      request<{ ok: boolean }>('/api/auth/logout-all', { method: 'POST' }),
    me: () => request<any>('/api/auth/me'),
  },

  users: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/users${qs}`);
    },
    create: (data: any) =>
      request<any>('/api/users', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) =>
      request<any>(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  },

  agents: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number; page: number; limit: number }>(`/api/agents${qs}`);
    },
    get: (id: string) => request<any>(`/api/agents/${id}`),
    delete: (id: string) => request<any>(`/api/agents/${id}`, { method: 'DELETE' }),
    stats: () => request<any>('/api/agents/stats'),
    move: (id: string, data: any) =>
      request<any>(`/api/agents/${id}/move`, { method: 'POST', body: JSON.stringify(data) }),
    inventory: (id: string) => request<any>(`/api/agents/${id}/inventory`),
    metrics: (id: string, hours?: number) =>
      request<{ data: any[]; agent_id: string; period_hours: number }>(
        `/api/agents/${id}/metrics?hours=${hours ?? 24}`
      ),
    collectInventory: (id: string) =>
      request<any>(`/api/agents/${id}/collect-inventory`, { method: 'POST' }),
    updateBulk: (agentIds: string[], force = false) =>
      request<any>('/api/agents/update', { method: 'POST', body: JSON.stringify({ agent_ids: agentIds, force }) }),
    updateManifest: () =>
      request<{ version: string; available: boolean }>('/api/agents/update/manifest'),
  },

  jobs: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number; page: number; limit: number }>(`/api/jobs${qs}`);
    },
    get: (id: string) => request<any>(`/api/jobs/${id}`),
    create: (data: any) =>
      request<any>('/api/jobs', {
        method: 'POST',
        body: JSON.stringify((() => {
          // Backward/forward compatibility for UI callers.
          // Backend expects CreateJobSchema: { agent_id, job_type, payload, ... }.
          const body = { ...(data ?? {}) };
          if (!body.job_type && body.type) {
            body.job_type = body.type;
            delete body.type;
          }

          // UI previously put timeout in payload as timeout_secs.
          if (body.payload && typeof body.payload === 'object') {
            if (body.payload.timeout_secs !== undefined && body.timeout_sec === undefined) {
              body.timeout_sec = body.payload.timeout_secs;
              delete body.payload.timeout_secs;
            }
            // If payload has timeout_sec, prefer it as the job timeout unless explicitly set.
            if (body.payload.timeout_sec !== undefined && body.timeout_sec === undefined) {
              body.timeout_sec = body.payload.timeout_sec;
            }
          }

          return body;
        })()),
      }),
    cancel: (id: string) =>
      request<any>(`/api/jobs/${id}/cancel`, { method: 'POST' }),
    stats: () => request<any>('/api/jobs/stats'),
  },

  audit: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number; page: number; limit: number }>(`/api/audit${qs}`);
    },
  },

  enrollment: {
    tokens: {
      list: (params?: Record<string, string>) => {
        const qs = params ? '?' + new URLSearchParams(params).toString() : '';
        return request<{ data: any[]; total: number }>(`/api/enrollment/tokens${qs}`);
      },
      create: (data: any) =>
        request<any>('/api/enrollment/tokens', { method: 'POST', body: JSON.stringify(data) }),
      revoke: (id: string) =>
        request<any>(`/api/enrollment/tokens/${id}/revoke`, { method: 'POST' }),
      delete: (id: string) =>
        request<any>(`/api/enrollment/tokens/${id}`, { method: 'DELETE' }),
      commands: (id: string) => request<any>(`/api/enrollment/tokens/${id}/commands`),
    },
  },

  companies: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/companies${qs}`);
    },
    get: (id: string) => request<any>(`/api/companies/${id}`),
    create: (data: any) =>
      request<any>('/api/companies', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) =>
      request<any>(`/api/companies/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: string) =>
      request<any>(`/api/companies/${id}`, { method: 'DELETE' }),
  },

  folders: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/folders${qs}`);
    },
    get: (id: string) => request<any>(`/api/folders/${id}`),
    create: (data: any) =>
      request<any>('/api/folders', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) =>
      request<any>(`/api/folders/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: string) =>
      request<any>(`/api/folders/${id}`, { method: 'DELETE' }),
  },

  vault: {
    list: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/vault/secrets${qs}`);
    },
    create: (data: any) =>
      request<any>('/api/vault/secrets', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: string, data: any) =>
      request<any>(`/api/vault/secrets/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: string) =>
      request<any>(`/api/vault/secrets/${id}`, { method: 'DELETE' }),
    reveal: (id: string, mfa_code: string) =>
      request<any>(`/api/vault/secrets/${id}/reveal`, { method: 'POST', body: JSON.stringify({ mfa_code }) }),
    use: (
      id: string,
      data: {
        agent_id: string;
        job_type: string;
        payload: Record<string, unknown>;
        reason?: string;
        priority?: number;
        timeout_sec?: number;
        injection?: {
          mode?: 'replace' | 'env';
          placeholder?: string;
          target_field?: string;
          env_key?: string;
        };
      },
    ) => request<any>(`/api/vault/secrets/${id}/use`, { method: 'POST', body: JSON.stringify(data) }),
    accessLogs: (id: string) =>
      request<{ data: any[] }>(`/api/vault/secrets/${id}/access-logs`),
    
    // Premium: Versioning
    versions: (id: string) =>
      request<{ data: any[] }>(`/api/vault/secrets/${id}/versions`),
    revealVersion: (id: string, versionId: string, mfa_code: string) =>
      request<{ value: string }>(`/api/vault/secrets/${id}/versions/${versionId}/reveal`, { method: 'POST', body: JSON.stringify({ mfa_code }) }),
    
    // Premium: Sharing
    permissions: (id: string) =>
      request<{ data: any[] }>(`/api/vault/secrets/${id}/permissions`),
    share: (id: string, data: { principal_type: string; principal_id: string; rights: string[] }) =>
      request<any>(`/api/vault/secrets/${id}/share`, { method: 'POST', body: JSON.stringify(data) }),
    revokePermission: (id: string, permId: string) =>
      request<any>(`/api/vault/secrets/${id}/permissions/${permId}`, { method: 'DELETE' }),
    
    // Premium: Rotation
    expiring: (days?: number) => {
      const qs = days ? `?days=${days}` : '';
      return request<{ data: any[] }>(`/api/vault/expiring${qs}`);
    },
    rotate: (id: string) =>
      request<any>(`/api/vault/secrets/${id}/rotate`, { method: 'POST' }),
  },

  chat: {
    channels: {
      list: () => request<{ data: any[] }>('/api/chat/channels'),
      create: (data: any) =>
        request<any>('/api/chat/channels', { method: 'POST', body: JSON.stringify(data) }),
      messages: (id: string, params?: Record<string, string>) => {
        const qs = params ? '?' + new URLSearchParams(params).toString() : '';
        return request<{ data: any[]; total: number }>(`/api/chat/channels/${id}/messages${qs}`);
      },
      sendMessage: (id: string, data: any) =>
        request<any>(`/api/chat/channels/${id}/messages`, { method: 'POST', body: JSON.stringify(data) }),
      addMember: (id: string, userId: string) =>
        request<any>(`/api/chat/channels/${id}/members`, { method: 'POST', body: JSON.stringify({ user_id: userId }) }),
      removeMember: (id: string, userId: string) =>
        request<any>(`/api/chat/channels/${id}/members/${userId}`, { method: 'DELETE' }),
    },
  },

  edr: {
    events: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/edr/events${qs}`);
    },
    detections: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/edr/detections${qs}`);
    },
    updateDetection: (id: string, data: any) =>
      request<any>(`/api/edr/detections/${id}/status`, { method: 'PATCH', body: JSON.stringify(data) }),
    incidents: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/edr/incidents${qs}`);
    },
    createIncident: (data: any) =>
      request<any>('/api/edr/incidents', { method: 'POST', body: JSON.stringify(data) }),
    updateIncident: (id: string, data: any) =>
      request<any>(`/api/edr/incidents/${id}/status`, { method: 'PATCH', body: JSON.stringify(data) }),
    respond: (data: any) =>
      request<any>('/api/edr/respond', { method: 'POST', body: JSON.stringify(data) }),
  },

  admin: {
    users: {
      list: (params?: Record<string, string>) => {
        const qs = params ? '?' + new URLSearchParams(params).toString() : '';
        return request<{ data: any[]; total: number }>(`/api/admin/users${qs}`);
      },
      create: (data: any) =>
        request<any>('/api/admin/users', { method: 'POST', body: JSON.stringify(data) }),
      update: (id: string, data: any) =>
        request<any>(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      suspend: (id: string, active: boolean) =>
        request<any>(`/api/admin/users/${id}/suspend`, { method: 'POST', body: JSON.stringify({ active }) }),
      changeRole: (id: string, role: string) =>
        request<any>(`/api/admin/users/${id}/role`, { method: 'PATCH', body: JSON.stringify({ role }) }),
      getSessions: (id: string) =>
        request<any[]>(`/api/admin/users/${id}/sessions`),
      revokeAllSessions: (id: string) =>
        request<any>(`/api/admin/users/${id}/sessions/revoke-all`, { method: 'POST' }),
      setupMFA: (id: string) =>
        request<{ ok: boolean; secret: string; totp_uri: string }>(`/api/admin/users/${id}/mfa/setup`, { method: 'POST' }),
      enableMFA: (id: string) =>
        request<any>(`/api/admin/users/${id}/mfa/enable`, { method: 'POST' }),
      disableMFA: (id: string) =>
        request<any>(`/api/admin/users/${id}/mfa/disable`, { method: 'POST' }),
    },
    sessions: {
      revoke: (id: string) =>
        request<any>(`/api/admin/sessions/${id}`, { method: 'DELETE' }),
    },
    roles: {
      list: () =>
        request<any[]>('/api/admin/roles'),
    },
    teams: {
      list: () => request<{ data: any[] }>('/api/admin/teams'),
      create: (data: any) =>
        request<any>('/api/admin/teams', { method: 'POST', body: JSON.stringify(data) }),
      update: (id: string, data: any) =>
        request<any>(`/api/admin/teams/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      delete: (id: string) =>
        request<any>(`/api/admin/teams/${id}`, { method: 'DELETE' }),
      members: (id: string) =>
        request<{ data: any[] }>(`/api/admin/teams/${id}/members`),
      addMember: (id: string, userId: string) =>
        request<any>(`/api/admin/teams/${id}/members`, { method: 'POST', body: JSON.stringify({ user_id: userId }) }),
      removeMember: (id: string, userId: string) =>
        request<any>(`/api/admin/teams/${id}/members/${userId}`, { method: 'DELETE' }),
    },
    policies: {
      list: () => request<{ data: any[] }>('/api/admin/policies'),
      update: (id: string, data: any) =>
        request<any>(`/api/admin/policies/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    },
    loginEvents: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/admin/login-events${qs}`);
    },
  },

  // ── Alerting ──
  alerts: {
    rules: {
      list: (params?: Record<string, string>) => {
        const qs = params ? '?' + new URLSearchParams(params).toString() : '';
        return request<{ data: any[]; total: number }>(`/api/alerts/rules${qs}`);
      },
      get: (id: string) => request<any>(`/api/alerts/rules/${id}`),
      create: (data: any) =>
        request<any>('/api/alerts/rules', { method: 'POST', body: JSON.stringify(data) }),
      update: (id: string, data: any) =>
        request<any>(`/api/alerts/rules/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      delete: (id: string) =>
        request<any>(`/api/alerts/rules/${id}`, { method: 'DELETE' }),
    },
    events: {
      list: (params?: Record<string, string>) => {
        const qs = params ? '?' + new URLSearchParams(params).toString() : '';
        return request<{ data: any[]; total: number }>(`/api/alerts/events${qs}`);
      },
      get: (id: string) => request<any>(`/api/alerts/events/${id}`),
      ack: (id: string, note?: string) =>
        request<any>(`/api/alerts/events/${id}/ack`, { method: 'POST', body: JSON.stringify({ note }) }),
      resolve: (id: string, note?: string) =>
        request<any>(`/api/alerts/events/${id}/resolve`, { method: 'POST', body: JSON.stringify({ note }) }),
      snooze: (id: string, duration_min: number, note?: string) =>
        request<any>(`/api/alerts/events/${id}/snooze`, { method: 'POST', body: JSON.stringify({ duration_min, note }) }),
    },
    stats: () => request<any>('/api/alerts/stats'),
    integrations: {
      list: () => request<{ data: any[] }>('/api/alerts/integrations'),
      create: (data: any) =>
        request<any>('/api/alerts/integrations', { method: 'POST', body: JSON.stringify(data) }),
      update: (id: string, data: any) =>
        request<any>(`/api/alerts/integrations/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      delete: (id: string) =>
        request<any>(`/api/alerts/integrations/${id}`, { method: 'DELETE' }),
    },
    test: (channel: string) =>
      request<any>('/api/alerts/test', { method: 'POST', body: JSON.stringify({ channel }) }),
  },

  // ── API Keys ──
  apiKeys: {
    list: () => request<{ data: any[] }>('/api/api-keys'),
    create: (data: { name: string; scopes?: string[]; expires_at?: string }) =>
      request<any>('/api/api-keys', { method: 'POST', body: JSON.stringify(data) }),
    revoke: (id: string) =>
      request<any>(`/api/api-keys/${id}/revoke`, { method: 'PATCH' }),
    delete: (id: string) =>
      request<any>(`/api/api-keys/${id}`, { method: 'DELETE' }),
  },

  // ── Zabbix Deploy ──
  deploy: {
    import: (data: {
      csv_content: string; filename: string; mode: string;
      zabbix_url: string; zabbix_user: string; zabbix_password: string;
      zabbix_script?: string; server_url: string;
    }) =>
      request<any>('/api/deploy/zabbix/import', { method: 'POST', body: JSON.stringify(data) }),
    validate: (batchId: string, zabbix_password: string) =>
      request<any>(`/api/deploy/zabbix/validate/${batchId}`, { method: 'POST', body: JSON.stringify({ zabbix_password }) }),
    start: (batchId: string) =>
      request<any>(`/api/deploy/zabbix/start/${batchId}`, { method: 'POST' }),
    retry: (batchId: string) =>
      request<any>(`/api/deploy/zabbix/retry/${batchId}`, { method: 'POST' }),
    cancel: (batchId: string) =>
      request<any>(`/api/deploy/zabbix/cancel/${batchId}`, { method: 'POST' }),
    batches: (params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[]; total: number }>(`/api/deploy/zabbix/batches${qs}`);
    },
    batch: (batchId: string) =>
      request<any>(`/api/deploy/zabbix/batches/${batchId}`),
    items: (batchId: string, params?: Record<string, string>) => {
      const qs = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<{ data: any[] }>(`/api/deploy/zabbix/batches/${batchId}/items${qs}`);
    },
  },
};
