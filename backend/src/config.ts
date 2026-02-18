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

const nodeEnv = env('NODE_ENV', 'development');

// Dev defaults are tuned for the repo's docker-compose.yml (dev).
// They intentionally avoid host port 5432 (often already in use).
const devPgHost = process.env.PG_HOST ?? 'localhost';
const devPgPort = process.env.PG_PORT ?? '5433';
const devDatabaseUrl = `postgresql://reap3r:reap3r_dev_password@${devPgHost}:${devPgPort}/reap3r`;

export const config = {
  nodeEnv,
  port: envInt('PORT', 4000),
  wsPort: envInt('WS_PORT', 4001),
  uiWsPort: envInt('UI_WS_PORT', 4002),

  // Database
  database: {
    // In production we require DATABASE_URL explicitly to avoid silently pointing at the wrong DB.
    url: nodeEnv === 'development' ? env('DATABASE_URL', devDatabaseUrl) : env('DATABASE_URL'),
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

  // SMTP / Email
  smtp: {
    host: env('SMTP_HOST', ''),
    port: envInt('SMTP_PORT', 587),
    secure: env('SMTP_SECURE', 'false') === 'true',
    user: env('SMTP_USER', ''),
    pass: env('SMTP_PASS', ''),
    from: env('SMTP_FROM', 'noreply@massvision.local'),
  },

  // Vault
  vault: {
    // VAULT_MASTER_KEY: required in production, dev falls back to HMAC_SECRET (but log warning)
    masterKey: process.env.VAULT_MASTER_KEY ?? (nodeEnv === 'production' ? (() => { throw new Error('VAULT_MASTER_KEY required in production'); })() : undefined),
  },
} as const;

// Validation — enforce non-default secrets in production
if (nodeEnv === 'production') {
  if (!process.env.VAULT_MASTER_KEY) {
    throw new Error('[FATAL] VAULT_MASTER_KEY must be set in production for secret decryption');
  }
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.startsWith('dev_')) {
    throw new Error('[FATAL] JWT_SECRET must be set to a strong secret in production');
  }
  if (!process.env.HMAC_SECRET || process.env.HMAC_SECRET.startsWith('dev_')) {
    throw new Error('[FATAL] HMAC_SECRET must be set to a strong secret in production');
  }
}
