// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Binary Distribution
// ─────────────────────────────────────────────
//
// Manifest + download endpoint used by bootstrap and remote update flows.
// Supports signed manifests and multi-arch Windows binaries.
//
import { FastifyInstance } from 'fastify';
import fs from 'node:fs';
import path from 'node:path';
import { AgentArch, AgentOs, loadAgentUpdateManifest, normalizeArch, resolveBinaryPath } from '../services/agent-update-manifest.service.js';

export default async function agentBinaryRoutes(fastify: FastifyInstance) {
  // Manifest: used by `bootstrap/` to find latest binary.
  fastify.get('/api/agent-binary/manifest', async (request, reply) => {
    const q = request.query as any;
    const os = String(q.os ?? '').toLowerCase() as AgentOs;
    const arch = normalizeArch(String(q.arch ?? 'x86_64')) as AgentArch;
    if (!resolveBinaryPath(os, arch)) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Unsupported os/arch' });
    }

    try {
      const manifest = await loadAgentUpdateManifest({ os, arch, request });
      return manifest;
    } catch (error: any) {
      const message = String(error?.message || 'Unable to resolve update manifest');
      const statusCode = message.includes('required but missing') ? 503 : 404;
      return reply.status(statusCode).send({ statusCode, error: statusCode === 503 ? 'Service Unavailable' : 'Not Found', message });
    }
  });

  // Download: returns raw binary bytes.
  fastify.get('/api/agent-binary/download', async (request, reply) => {
    const q = request.query as any;
    const os = String(q.os ?? '').toLowerCase() as AgentOs;
    const arch = normalizeArch(String(q.arch ?? 'x86_64')) as AgentArch;

    const resolved = resolveBinaryPath(os, arch);
    if (!resolved) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Unsupported os/arch' });
    }
    if (!fs.existsSync(resolved.filePath)) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Agent binary not found on server' });
    }

    // Build a stable filename regardless of what the on-disk filename is.
    // Example: reap3r-agent-windows-x86_64.exe
    const parsed = path.parse(resolved.fileName);
    const baseName = parsed.name; // strips extension
    const ext = os === 'windows' ? '.exe' : '';
    const downloadName = `${baseName}-${os}-${arch}${ext}`;
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', `attachment; filename="${downloadName}"`);
    return reply.send(fs.createReadStream(resolved.filePath));
  });
}
