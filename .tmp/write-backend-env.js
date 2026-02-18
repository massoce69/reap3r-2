const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function arg(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return fallback;
  return process.argv[idx + 1] ?? fallback;
}

const appDir = arg('--appdir', '/var/www/reap3r-2');
const procName = arg('--proc', 'reap3r-backend');

const raw = execSync('pm2 jlist', { encoding: 'utf8' });
const procs = JSON.parse(raw);
const p = procs.find((x) => x && x.name === procName);
if (!p) {
  console.error(`Missing PM2 process: ${procName}`);
  process.exit(2);
}

const env = (p.pm2_env && p.pm2_env.env) ? p.pm2_env.env : {};
const port = env.PORT || env.BACKEND_PORT || 4000;
const wsPort = env.WS_PORT || env.WEBSOCKET_PORT || 4001;

let out = '';
out += `NODE_ENV=production\n`;
out += `PORT=${port}\n`;
out += `WS_PORT=${wsPort}\n`;

const keys = [
  'API_BASE_URL',
  'DATABASE_URL',
  'JWT_SECRET',
  'HMAC_SECRET',
  'LOG_LEVEL',
];

for (const k of keys) {
  if (env[k] !== undefined && env[k] !== null && String(env[k]).length) {
    out += `${k}=${env[k]}\n`;
  }
}

for (const k of Object.keys(env)) {
  if (k.startsWith('AGENT_BINARY_PATH_')) {
    out += `${k}=${env[k]}\n`;
  }
}

const envPath = path.join(appDir, 'backend', '.env');
fs.mkdirSync(path.dirname(envPath), { recursive: true });
fs.writeFileSync(envPath, out, { mode: 0o600 });
console.log(`Wrote ${envPath}`);
