// ─────────────────────────────────────────────
// Seed enrollment token for agent testing
// Usage: DATABASE_URL=... npx tsx src/scripts/seed-test-token.ts
// ─────────────────────────────────────────────

import pg from 'pg';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('ERROR: DATABASE_URL environment variable is required.');
  process.exit(1);
}

const pool = new Pool({ connectionString });

async function run() {
  const client = await pool.connect();
  try {
    console.log('[seed-test-token] Starting...');

    // Get default org
    const orgRes = await client.query('SELECT id FROM orgs LIMIT 1');
    if ((orgRes.rowCount ?? 0) === 0) {
      console.error('ERROR: No organization found in DB!');
      process.exit(1);
    }
    const orgId = orgRes.rows[0].id;

    // Get default site
    const siteRes = await client.query('SELECT id FROM sites WHERE org_id = $1 LIMIT 1', [orgId]);
    const siteId = siteRes.rows[0]?.id || null;

    // Create a test enrollment token
    const tokenId = uuidv4();
    const token = 'test-enrollment-token-e2e';
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    const insertRes = await client.query(
      `INSERT INTO enrollment_tokens (id, org_id, site_id, name, token, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       ON CONFLICT (token) DO UPDATE SET expires_at = EXCLUDED.expires_at
       RETURNING id, token, expires_at`,
      [tokenId, orgId, siteId, 'E2E Agent Test Token', token, expiresAt]
    );

    const record = insertRes.rows[0];
    console.log('[seed-test-token] ✅ Created enrollment token');
    console.log(`  Token ID:    ${record.id}`);
    console.log(`  Token Value: ${record.token}`);
    console.log(`  Expires:     ${record.expires_at}`);
    console.log(`\n[seed-test-token] Use this token in agent-sim:`);
    console.log(`  npm run test:agent-sim -- --server=ws://localhost:4001 --token=${record.token}`);

  } finally {
    client.release();
    await pool.end();
  }
}

run().catch((err) => {
  console.error('[seed-test-token] Error:', err);
  process.exit(1);
});
