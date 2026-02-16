// ─────────────────────────────────────────────────────────
// MASSVISION Reap3r — Backend E2E Tests
// ─────────────────────────────────────────────────────────

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

const API_URL = process.env.TEST_API_URL || 'http://localhost:4000';
let token: string;
let agentId: string;
let jobId: string;
let enrollmentTokenId: string;

async function api(path: string, options: RequestInit = {}) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  const body = res.headers.get('content-type')?.includes('json')
    ? await res.json()
    : await res.text();
  return { status: res.status, body };
}

describe('Health', () => {
  it('GET /health returns ok', async () => {
    const { status, body } = await api('/health');
    expect(status).toBe(200);
    expect(body.status).toBe('ok');
  });

  it('GET /ready returns ok with database connected', async () => {
    const { status, body } = await api('/ready');
    expect(status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.database).toBe('connected');
  });
});

describe('Auth', () => {
  it('POST /api/auth/login with invalid creds returns 401', async () => {
    const { status } = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'bad@test.com', password: 'wrong' }),
    });
    expect(status).toBe(401);
  });

  it('POST /api/auth/login with valid creds returns token', async () => {
    const { status, body } = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin@massvision.local',
        password: 'Admin123!@#',
      }),
    });
    expect(status).toBe(200);
    expect(body.token).toBeDefined();
    expect(body.user.email).toBe('admin@massvision.local');
    expect(body.user.role).toBe('super_admin');
    token = body.token;
  });

  it('GET /api/auth/me returns current user', async () => {
    const { status, body } = await api('/api/auth/me');
    expect(status).toBe(200);
    expect(body.email).toBe('admin@massvision.local');
  });

  it('POST /api/users creates a technician', async () => {
    const { status, body } = await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({
        email: 'tech@massvision.local',
        password: 'TechPass123!',
        full_name: 'Test Technician',
        role: 'technician',
      }),
    });
    expect(status).toBe(201);
    expect(body.role).toBe('technician');
  });

  it('GET /api/users lists users', async () => {
    const { status, body } = await api('/api/users');
    expect(status).toBe(200);
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBeGreaterThanOrEqual(2);
  });
});

describe('Enrollment Tokens', () => {
  it('POST /api/enrollment-tokens creates a token', async () => {
    const { status, body } = await api('/api/enrollment-tokens', {
      method: 'POST',
      body: JSON.stringify({
        label: 'Test Token',
        max_uses: 10,
      }),
    });
    expect(status).toBe(201);
    expect(body.token).toBeDefined();
    expect(body.label).toBe('Test Token');
    enrollmentTokenId = body.id;
  });

  it('GET /api/enrollment-tokens lists tokens', async () => {
    const { status, body } = await api('/api/enrollment-tokens');
    expect(status).toBe(200);
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBeGreaterThanOrEqual(1);
  });

  it('GET /api/deployment/commands returns deploy commands', async () => {
    const tokensRes = await api('/api/enrollment-tokens');
    const tokenValue = tokensRes.body[0].token;

    const { status, body } = await api(`/api/deployment/commands?token=${tokenValue}`);
    expect(status).toBe(200);
    expect(body.windows).toContain('powershell');
    expect(body.linux).toContain('curl');
  });

  it('POST /api/enrollment-tokens/:id/revoke revokes token', async () => {
    const { status } = await api(`/api/enrollment-tokens/${enrollmentTokenId}/revoke`, {
      method: 'POST',
    });
    expect(status).toBe(200);
  });
});

describe('Agents', () => {
  it('GET /api/agents returns paginated list', async () => {
    const { status, body } = await api('/api/agents?page=1&limit=10');
    expect(status).toBe(200);
    expect(body.data).toBeDefined();
    expect(body.total).toBeDefined();
    expect(body.page).toBe(1);
  });

  it('GET /api/agents with search filter', async () => {
    const { status, body } = await api('/api/agents?search=nonexistent');
    expect(status).toBe(200);
    expect(body.data).toEqual([]);
  });

  it('GET /api/agents/:id returns 404 for unknown agent', async () => {
    const { status } = await api('/api/agents/00000000-0000-0000-0000-000000000000');
    expect(status).toBe(404);
  });
});

describe('Jobs', () => {
  it('GET /api/jobs returns paginated list', async () => {
    const { status, body } = await api('/api/jobs?page=1&limit=10');
    expect(status).toBe(200);
    expect(body.data).toBeDefined();
    expect(body.total).toBeDefined();
  });

  it('POST /api/jobs returns 400 for invalid payload', async () => {
    const { status } = await api('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({
        agent_id: '00000000-0000-0000-0000-000000000000',
        type: 'run_script',
        payload: {}, // missing required fields
      }),
    });
    expect([400, 404]).toContain(status);
  });

  it('GET /api/jobs/:id returns 404 for unknown job', async () => {
    const { status } = await api('/api/jobs/00000000-0000-0000-0000-000000000000');
    expect(status).toBe(404);
  });
});

describe('Audit Logs', () => {
  it('GET /api/audit-logs returns paginated list', async () => {
    const { status, body } = await api('/api/audit-logs?page=1&limit=10');
    expect(status).toBe(200);
    expect(body.data).toBeDefined();
    expect(body.total).toBeDefined();
    // Should have audit entries from login + user creation
    expect(body.total).toBeGreaterThan(0);
  });

  it('GET /api/audit-logs with action filter', async () => {
    const { status, body } = await api('/api/audit-logs?action=user.login');
    expect(status).toBe(200);
    expect(body.data.every((l: any) => l.action === 'user.login')).toBe(true);
  });
});

describe('RBAC', () => {
  let viewerToken: string;

  beforeAll(async () => {
    // Create viewer user
    await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({
        email: 'viewer@massvision.local',
        password: 'ViewerPass123!',
        full_name: 'Test Viewer',
        role: 'viewer',
      }),
    });

    // Login as viewer
    const { body } = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'viewer@massvision.local',
        password: 'ViewerPass123!',
      }),
    });
    viewerToken = body.token;
  });

  it('Viewer cannot create users', async () => {
    const { status } = await api('/api/users', {
      method: 'POST',
      headers: { Authorization: `Bearer ${viewerToken}` },
      body: JSON.stringify({
        email: 'new@test.com',
        password: 'Test123!!',
        full_name: 'New User',
        role: 'viewer',
      }),
    });
    expect(status).toBe(403);
  });

  it('Viewer cannot create enrollment tokens', async () => {
    const { status } = await api('/api/enrollment-tokens', {
      method: 'POST',
      headers: { Authorization: `Bearer ${viewerToken}` },
      body: JSON.stringify({ label: 'hack' }),
    });
    expect(status).toBe(403);
  });

  it('Viewer can read agents', async () => {
    const { status } = await api('/api/agents', {
      headers: { Authorization: `Bearer ${viewerToken}` },
    });
    expect(status).toBe(200);
  });

  it('Viewer can read jobs', async () => {
    const { status } = await api('/api/jobs', {
      headers: { Authorization: `Bearer ${viewerToken}` },
    });
    expect(status).toBe(200);
  });
});

describe('Security', () => {
  it('Unauthenticated requests return 401', async () => {
    const endpoints = ['/api/auth/me', '/api/agents', '/api/jobs', '/api/audit-logs'];
    for (const ep of endpoints) {
      const res = await fetch(`${API_URL}${ep}`);
      expect(res.status).toBe(401);
    }
  });

  it('Invalid JWT returns 401', async () => {
    const res = await fetch(`${API_URL}/api/agents`, {
      headers: { Authorization: 'Bearer invalid-token' },
    });
    expect(res.status).toBe(401);
  });
});
