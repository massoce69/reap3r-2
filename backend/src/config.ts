// ─────────────────────────────────────────────
// MASSVISION Reap3r — Backend Configuration
// ─────────────────────────────────────────────

function env(key: string, fallback?: string): string {
  const val = process.env[key] ?? fallback;
  if (val === undefined) throw new Error(`Missing required env var: ${key}`);
  return val;
}

function envInt(key: string, fallback: number): number {
  const raw = process.env[key];
  return raw ? parseInt(raw, 10) : fallback;
}

export const config = {
  nodeEnv: env('NODE_ENV', 'development'),
  port: envInt('PORT', 4000),
  wsPort: envInt('WS_PORT', 4001),

  // Database
  database: {
    url: env('DATABASE_URL', 'postgresql://reap3r:reap3r_secret@localhost:5432/reap3r'),
    poolMin: envInt('DB_POOL_MIN', 2),
    poolMax: envInt('DB_POOL_MAX', 20),
  },

  // JWT
  jwt: {
    secret: env('JWT_SECRET', 'dev_jwt_secret_change_in_production_00000000'),
    expiresIn: env('JWT_EXPIRES_IN', '24h'),
  },

  // Agent HMAC
  hmac: {
    secret: env('HMAC_SECRET', 'dev_hmac_secret_change_in_production_00000000'),
  },

  // Bcrypt
  bcryptRounds: envInt('BCRYPT_ROUNDS', 12),

  // API
  apiBaseUrl: env('API_BASE_URL', 'http://localhost:4000'),

  // Logging
  logLevel: env('LOG_LEVEL', 'info'),

  // Prometheus
  prometheusEnabled: env('PROMETHEUS_ENABLED', 'true') === 'true',

  // Agent heartbeat timeout (seconds)
  agentOfflineThresholdSecs: envInt('AGENT_OFFLINE_THRESHOLD_SECS', 90),
} as const;
