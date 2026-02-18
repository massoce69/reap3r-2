// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Binary Distribution
// ─────────────────────────────────────────────
//
// This provides a simple manifest + download endpoint used by the bootstrap watchdog.
// For now we only support linux/x86_64 from a locally built binary.
//
import { FastifyInstance } from 'fastify';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

type Os = 'linux' | 'windows' | 'darwin';
type Arch = 'x86_64' | 'aarch64';

function firstHeader(v: unknown): string | undefined {
  if (!v) return undefined;
  if (Array.isArray(v)) return String(v[0] ?? '');
  return String(v);
}

function publicBaseUrl(request: any): string {
  const proto = (firstHeader(request.headers['x-forwarded-proto']) || request.protocol || 'http')
    .split(',')[0]
    .trim();
  const host = (firstHeader(request.headers['x-forwarded-host']) || firstHeader(request.headers.host) || '')
    .split(',')[0]
    .trim();
  return host ? `${proto}://${host}` : (process.env.API_BASE_URL || 'http://localhost:4000');
}

function resolveBinaryPath(os: Os, arch: Arch): { filePath: string; fileName: string } | null {
  // Allow overriding via env (useful on VPS).
  const key = `AGENT_BINARY_PATH_${os.toUpperCase()}_${arch.toUpperCase()}`;
  const override = process.env[key];
  if (override && override.trim()) {
    return { filePath: override, fileName: path.basename(override) };
  }

  // Default: assume repo layout where backend runs from `<root>/backend`.
  if (os === 'linux' && arch === 'x86_64') {
    const filePath = path.resolve(process.cwd(), '../agent/target/release/reap3r-agent');
    return { filePath, fileName: 'reap3r-agent' };
  }

  return null;
}

async function sha256File(filePath: string): Promise<{ sha256: string; size: number }> {
  const stat = await fs.promises.stat(filePath);
  const hash = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const s = fs.createReadStream(filePath);
    s.on('data', (d) => hash.update(d));
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  return { sha256: hash.digest('hex'), size: stat.size };
}

export default async function agentBinaryRoutes(fastify: FastifyInstance) {
  // Manifest: used by `bootstrap/` to find latest binary.
  fastify.get('/api/agent-binary/manifest', async (request, reply) => {
    const q = request.query as any;
    const os = String(q.os ?? '').toLowerCase() as Os;
    const arch = String(q.arch ?? '').toLowerCase() as Arch;

    const resolved = resolveBinaryPath(os, arch);
    if (!resolved) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Unsupported os/arch' });
    }

    const exists = fs.existsSync(resolved.filePath);
    if (!exists) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message:
          `Agent binary not available on server for ${os}/${arch}. ` +
          `Build it on the server (e.g. in <repo>/agent: cargo build --release).`,
      });
    }

    const { sha256, size } = await sha256File(resolved.filePath);
    const base = publicBaseUrl(request);
    const download_url = `${base}/api/agent-binary/download?os=${encodeURIComponent(os)}&arch=${encodeURIComponent(arch)}`;

    return {
      version: process.env.AGENT_VERSION || '1.0.0',
      sha256,
      download_url,
      size,
    };
  });

  // Download: returns raw binary bytes.
  fastify.get('/api/agent-binary/download', async (request, reply) => {
    const q = request.query as any;
    const os = String(q.os ?? '').toLowerCase() as Os;
    const arch = String(q.arch ?? '').toLowerCase() as Arch;

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
