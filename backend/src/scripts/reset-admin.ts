// ─────────────────────────────────────────────
// MASSVISION Reap3r — Reset Admin Password
// Usage: DATABASE_URL=... npx tsx src/scripts/reset-admin.ts
//    or: npm run db:reset-admin
// ─────────────────────────────────────────────
import pg from 'pg';
import bcrypt from 'bcrypt';

const { Pool } = pg;

// Use DATABASE_URL directly (avoid importing config which requires other env vars)
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('ERROR: DATABASE_URL environment variable is required.');
  console.error('Example: DATABASE_URL=postgresql://reap3r:reap3r_secret@localhost:5432/reap3r npx tsx src/scripts/reset-admin.ts');
  process.exit(1);
}

const pool = new Pool({ connectionString });

const ADMIN_EMAIL = process.env.REAP3R_ADMIN_EMAIL || 'admin@massvision.local';
const ADMIN_PASSWORD_ENV = process.env.REAP3R_ADMIN_PASSWORD;
if (!ADMIN_PASSWORD_ENV) {
  console.error('ERROR: REAP3R_ADMIN_PASSWORD environment variable is required.');
  console.error('Example:');
  console.error('  REAP3R_ADMIN_PASSWORD=... DATABASE_URL=... npx tsx src/scripts/reset-admin.ts');
  process.exit(1);
}
const ADMIN_PASSWORD: string = ADMIN_PASSWORD_ENV;

async function run() {
  const client = await pool.connect();
  try {
    console.log('[reset-admin] Starting...');
    console.log('[reset-admin] Target email:', ADMIN_EMAIL);

    // 1. Generate bcrypt hash
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

    // 2. Verify hash works BEFORE writing to DB
    const verifyBefore = await bcrypt.compare(ADMIN_PASSWORD, hash);
    console.log('[reset-admin] Hash self-verification:', verifyBefore ? 'PASS' : 'FAIL');
    if (!verifyBefore) {
      console.error('[reset-admin] FATAL: bcrypt hash self-verification failed!');
      process.exit(1);
    }

    // 3. Check if user exists
    const checkRes = await client.query(
      'SELECT id, email, role, is_active, is_suspended, failed_login_count, locked_until, password_hash FROM users WHERE email = $1',
      [ADMIN_EMAIL]
    );

    if (checkRes.rowCount === 0) {
      console.log('[reset-admin] User not found, creating...');
      const orgRes = await client.query('SELECT id FROM orgs LIMIT 1');
      if ((orgRes.rowCount ?? 0) === 0) {
        console.error('[reset-admin] FATAL: No organization found in DB!');
        process.exit(1);
      }
      const orgId = orgRes.rows[0].id;
      const insertRes = await client.query(
        'INSERT INTO users (org_id, email, name, password_hash, role, is_active) VALUES ($1, $2, $3, $4, $5, true) RETURNING id, email',
        [orgId, ADMIN_EMAIL, 'System Admin', hash, 'super_admin']
      );
      console.log('[reset-admin] CREATED user:', insertRes.rows[0]);
    } else {
      const user = checkRes.rows[0];
      console.log('[reset-admin] Found user:', { id: user.id, role: user.role, is_active: user.is_active, is_suspended: user.is_suspended, failed_login_count: user.failed_login_count, locked_until: user.locked_until });

      // 4. Update password + unlock + unsuspend + activate
      const updateRes = await client.query(
        'UPDATE users SET password_hash = $1, is_active = true, is_suspended = false, failed_login_count = 0, locked_until = NULL WHERE email = $2 RETURNING id, email',
        [hash, ADMIN_EMAIL]
      );
      console.log('[reset-admin] UPDATED user:', updateRes.rows[0]);
    }

    // 5. Final verification: read back and compare
    const finalRes = await client.query('SELECT password_hash FROM users WHERE email = $1', [ADMIN_EMAIL]);
    const storedHash = finalRes.rows[0]?.password_hash;
    const verifyAfter = await bcrypt.compare(ADMIN_PASSWORD, storedHash);
    console.log('[reset-admin] Final DB verification:', verifyAfter ? 'PASS' : 'FAIL');

    if (verifyAfter) {
      console.log('\n[reset-admin] SUCCESS! You can now login with:');
      console.log('  Email:    ' + ADMIN_EMAIL);
      console.log('  Password: (the one you set in REAP3R_ADMIN_PASSWORD)');
    } else {
      console.error('\n[reset-admin] FAILED! Hash stored in DB does not match password.');
      process.exit(1);
    }
  } catch (err) {
    console.error('[reset-admin] Error:', err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

run();
