// ─────────────────────────────────────────────
// MASSVISION Reap3r — Messaging Service
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';

export async function createChannel(orgId: string, data: {
  name: string; type: string; company_id?: string; member_ids?: string[];
}) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO channels (org_id, name, type, company_id) VALUES ($1,$2,$3,$4) RETURNING id`,
    [orgId, data.name, data.type, data.company_id ?? null]
  );
  const channelId = rows[0].id;

  if (data.member_ids?.length) {
    const placeholders = data.member_ids.map((_, i) => `($1, $${i + 2})`).join(', ');
    await query(
      `INSERT INTO channel_members (channel_id, user_id) VALUES ${placeholders} ON CONFLICT DO NOTHING`,
      [channelId, ...data.member_ids]
    );
  }

  return { id: channelId };
}

export async function listChannels(orgId: string, userId: string) {
  const { rows } = await query(
    `SELECT c.*, (SELECT COUNT(*) FROM channel_members cm WHERE cm.channel_id = c.id)::int AS member_count
     FROM channels c
     WHERE c.org_id = $1 AND (c.type = 'general' OR c.id IN (SELECT channel_id FROM channel_members WHERE user_id = $2))
     ORDER BY c.last_message_at DESC NULLS LAST, c.name ASC`,
    [orgId, userId]
  );
  return rows;
}

export async function getChannelById(orgId: string, channelId: string) {
  const { rows } = await query(
    `SELECT c.*, (SELECT COUNT(*) FROM channel_members cm WHERE cm.channel_id = c.id)::int AS member_count
     FROM channels c WHERE c.org_id = $1 AND c.id = $2`,
    [orgId, channelId]
  );
  return rows[0] ?? null;
}

export async function addChannelMember(channelId: string, userId: string, role = 'member') {
  await query(
    `INSERT INTO channel_members (channel_id, user_id, role) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
    [channelId, userId, role]
  );
}

export async function removeChannelMember(channelId: string, userId: string) {
  await query(`DELETE FROM channel_members WHERE channel_id = $1 AND user_id = $2`, [channelId, userId]);
}

export async function getChannelMembers(channelId: string) {
  const { rows } = await query(
    `SELECT cm.*, u.name, u.email FROM channel_members cm JOIN users u ON u.id = cm.user_id WHERE cm.channel_id = $1 ORDER BY u.name`,
    [channelId]
  );
  return rows;
}

export async function createMessage(channelId: string, userId: string, body: string) {
  const { rows } = await query<{ id: string; created_at: string }>(
    `INSERT INTO messages (channel_id, user_id, body) VALUES ($1,$2,$3) RETURNING id, created_at`,
    [channelId, userId, body]
  );
  // Update last_message_at
  await query(`UPDATE channels SET last_message_at = NOW() WHERE id = $1`, [channelId]);
  return rows[0];
}

export async function listMessages(channelId: string, params: { page: number; limit: number }) {
  const offset = (params.page - 1) * params.limit;
  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT m.*, u.name AS user_name FROM messages m JOIN users u ON u.id = m.user_id
       WHERE m.channel_id = $1 ORDER BY m.created_at DESC LIMIT $2 OFFSET $3`,
      [channelId, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM messages WHERE channel_id = $1`, [channelId]),
  ]);
  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}
