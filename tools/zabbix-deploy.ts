// MASSVISION Reap3r - Zabbix local deploy helper
// Usage: npx tsx tools/zabbix-deploy.ts <csv_file> [--dry]
//
// Required env vars:
//   ZABBIX_URL
//   ZABBIX_USER
//   ZABBIX_PASS
//
// Optional:
//   REAP3R_SERVER_URL (default: https://reap3r.massvision.pro)

import { parseArgs } from 'node:util';
import fs from 'node:fs';

const REAP3R_SERVER_URL = process.env.REAP3R_SERVER_URL || 'https://reap3r.massvision.pro';
const ZABBIX_URL = process.env.ZABBIX_URL || '';
const ZABBIX_USER = process.env.ZABBIX_USER || '';
const ZABBIX_PASS = process.env.ZABBIX_PASS || '';
const ZABBIX_SCRIPT_NAME = 'Reap3rEnroll';

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: {
    help: { type: 'boolean', short: 'h' },
    dry: { type: 'boolean', short: 'd' },
  },
});

if (values.help || positionals.length === 0) {
  console.log(`
Usage: npx tsx tools/zabbix-deploy.ts <csv_file> [options]

Options:
  --dry, -d   Dry run (validate only, do not execute script)
  --help, -h  Show this help

CSV format:
  <dat_token>;<hostname>
  OR
  <hostname>;<dat_token>
`);
  process.exit(0);
}

if (!ZABBIX_URL || !ZABBIX_USER || !ZABBIX_PASS) {
  console.error('Missing required env vars: ZABBIX_URL, ZABBIX_USER, ZABBIX_PASS');
  process.exit(1);
}

const csvFile = positionals[0];
const dryRun = values.dry ?? false;
const HEX64 = /^[a-f0-9]{64}$/i;

async function rpc(method: string, params: any, auth: string | null = null) {
  const body = {
    jsonrpc: '2.0',
    method,
    params,
    id: Date.now(),
    auth,
  };

  const res = await fetch(ZABBIX_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json-rpc' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  }
  const json = await res.json() as any;
  if (json.error) {
    throw new Error(`Zabbix API Error: ${json.error.message} (${json.error.data})`);
  }
  return json.result;
}

function parseCsvTargets(input: string): Array<{ hostname: string; token: string }> {
  const lines = input.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const items: Array<{ hostname: string; token: string }> = [];

  for (const line of lines) {
    const sep = line.includes(';') ? ';' : line.includes('\t') ? '\t' : ',';
    const cols = line.split(sep).map((col) => col.trim().replace(/^["']|["']$/g, ''));
    if (cols.length < 2) continue;

    let hostname = '';
    let token = '';

    if (HEX64.test(cols[0])) {
      token = cols[0];
      hostname = cols[1];
    } else if (HEX64.test(cols[1])) {
      token = cols[1];
      hostname = cols[0];
    }

    if (hostname && token) {
      items.push({ hostname, token });
    }
  }

  return items;
}

async function main() {
  console.log('---------------------------------------------');
  console.log('   MASSVISION Reap3r - Zabbix Local Deploy');
  console.log('---------------------------------------------');
  console.log(`Reap3r server: ${REAP3R_SERVER_URL}`);

  console.log(`[1/4] Reading file: ${csvFile}`);
  const content = fs.readFileSync(csvFile, 'utf-8');
  const items = parseCsvTargets(content);
  if (items.length === 0) {
    throw new Error('No valid rows found (need hostname + 64-char DAT token)');
  }
  console.log(`Found ${items.length} deploy target(s).`);

  console.log('[2/4] Authenticating with Zabbix...');
  let authToken = '';
  if (HEX64.test(ZABBIX_PASS)) {
    authToken = ZABBIX_PASS;
    console.log('Using ZABBIX_PASS as API token.');
  } else {
    let attempts = 3;
    while (attempts > 0) {
      try {
        authToken = await rpc('user.login', { user: ZABBIX_USER, password: ZABBIX_PASS });
        console.log('Authenticated.');
        break;
      } catch (err: any) {
        attempts -= 1;
        if (attempts === 0) throw err;
        console.warn(`Auth failed, retrying (${attempts} left): ${String(err?.message || err)}`);
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
  }

  console.log('[3/4] Resolving script and hosts...');
  const scripts = await rpc(
    'script.get',
    { filter: { name: ZABBIX_SCRIPT_NAME }, output: ['scriptid'] },
    authToken,
  );
  if (!Array.isArray(scripts) || scripts.length === 0) {
    throw new Error(`Zabbix global script "${ZABBIX_SCRIPT_NAME}" not found`);
  }
  const scriptId = scripts[0].scriptid;
  console.log(`Script "${ZABBIX_SCRIPT_NAME}" found (ID: ${scriptId})`);

  const hostnames = items.map((item) => item.hostname);
  const hosts = await rpc(
    'host.get',
    { filter: { host: hostnames }, output: ['hostid', 'host'] },
    authToken,
  );
  const hostMap = new Map<string, string>();
  for (const host of hosts as Array<{ host: string; hostid: string }>) {
    hostMap.set(host.host, host.hostid);
  }
  console.log(`Resolved ${hostMap.size}/${items.length} host(s).`);

  if (dryRun) {
    console.log('[DRY-RUN] Stopping after validation.');
    process.exit(0);
  }

  console.log('[4/4] Executing script on hosts...');
  let success = 0;
  let failed = 0;
  let skipped = 0;

  for (const item of items) {
    const hostId = hostMap.get(item.hostname);
    if (!hostId) {
      console.log(`[SKIP] Host not found: ${item.hostname}`);
      skipped += 1;
      continue;
    }

    try {
      let result: any;
      try {
        result = await rpc(
          'script.execute',
          {
            scriptid: scriptId,
            hostid: hostId,
            manualinput: `${REAP3R_SERVER_URL} ${item.token}`,
          },
          authToken,
        );
      } catch (err: any) {
        const msg = String(err?.message || '').toLowerCase();
        const manualInputUnsupported =
          msg.includes('manualinput') ||
          msg.includes('unexpected parameter') ||
          msg.includes('invalid parameter');
        if (!manualInputUnsupported) throw err;
        console.warn(`[WARN] manualinput unsupported on ${item.hostname}, retrying without it`);
        result = await rpc(
          'script.execute',
          { scriptid: scriptId, hostid: hostId },
          authToken,
        );
      }

      const response = String(result?.response || '').toLowerCase();
      if (response === 'success') {
        console.log(`[OK] ${item.hostname}: ${String(result?.value || '')}`);
        success += 1;
      } else {
        console.log(`[ERR] ${item.hostname}: ${String(result?.value || result?.response || 'unknown response')}`);
        failed += 1;
      }
    } catch (err: any) {
      console.log(`[ERR] ${item.hostname}: ${String(err?.message || err)}`);
      failed += 1;
    }
  }

  console.log('---------------------------------------------');
  console.log(`Success: ${success}`);
  console.log(`Failed : ${failed}`);
  console.log(`Skipped: ${skipped}`);
  console.log('---------------------------------------------');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
