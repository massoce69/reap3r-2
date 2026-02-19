import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type AgentOs = 'linux' | 'windows' | 'darwin';
export type AgentArch = 'x86_64' | 'aarch64' | 'x86';

export type AgentUpdateManifest = {
  version: string;
  sha256: string;
  download_url: string;
  size: number;
  sig_ed25519?: string;
  signed_at?: string;
  signer_thumbprint?: string;
  require_authenticode?: boolean;
  manifest_source: 'signed' | 'generated' | 'generated_signed';
};

type ManifestInput = {
  version?: string;
  sha256?: string;
  download_url?: string;
  sig_ed25519?: string;
  signed_at?: string;
  signer_thumbprint?: string;
  require_authenticode?: boolean;
};

function firstHeader(v: unknown): string | undefined {
  if (!v) return undefined;
  if (Array.isArray(v)) return String(v[0] ?? '');
  return String(v);
}

export function publicBaseUrl(request: any): string {
  const proto = (firstHeader(request?.headers?.['x-forwarded-proto']) || request?.protocol || 'http')
    .split(',')[0]
    .trim();
  const host = (firstHeader(request?.headers?.['x-forwarded-host']) || firstHeader(request?.headers?.host) || '')
    .split(',')[0]
    .trim();
  return host ? `${proto}://${host}` : (process.env.API_BASE_URL || 'http://localhost:4000');
}

export function normalizeArch(arch: string): AgentArch {
  const raw = String(arch || '').toLowerCase();
  if (raw === 'amd64' || raw === 'x64') return 'x86_64';
  if (raw === 'i686' || raw === 'i386') return 'x86';
  if (raw === 'arm64') return 'aarch64';
  return (raw as AgentArch) || 'x86_64';
}

export function resolveBinaryPath(os: AgentOs, arch: AgentArch): { filePath: string; fileName: string } | null {
  const key = `AGENT_BINARY_PATH_${os.toUpperCase()}_${arch.toUpperCase()}`;
  const override = process.env[key];
  if (override && override.trim()) {
    return { filePath: override, fileName: path.basename(override) };
  }

  if (os === 'linux' && arch === 'x86_64') {
    const filePath = path.resolve(process.cwd(), '../agent/target/release/reap3r-agent');
    return { filePath, fileName: 'reap3r-agent' };
  }

  if (os === 'windows' && arch === 'x86_64') {
    const filePath = path.resolve(process.cwd(), '../agent/target/x86_64-pc-windows-msvc/release/reap3r-agent.exe');
    return { filePath, fileName: 'reap3r-agent.exe' };
  }

  if (os === 'windows' && arch === 'x86') {
    const filePath = path.resolve(process.cwd(), '../agent/target/i686-pc-windows-msvc/release/reap3r-agent.exe');
    return { filePath, fileName: 'reap3r-agent.exe' };
  }

  if (os === 'darwin' && arch === 'x86_64') {
    const filePath = path.resolve(process.cwd(), '../agent/target/x86_64-apple-darwin/release/reap3r-agent');
    return { filePath, fileName: 'reap3r-agent' };
  }

  if (os === 'darwin' && arch === 'aarch64') {
    const filePath = path.resolve(process.cwd(), '../agent/target/aarch64-apple-darwin/release/reap3r-agent');
    return { filePath, fileName: 'reap3r-agent' };
  }

  return null;
}

export async function sha256File(filePath: string): Promise<{ sha256: string; size: number }> {
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

function boolEnv(v: string | undefined, fallback = false): boolean {
  const raw = String(v ?? '').trim().toLowerCase();
  if (!raw) return fallback;
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function ed25519Pkcs8FromRaw32(raw: Buffer): Buffer {
  // PKCS#8 (RFC 8410) wrapper for Ed25519 private key.
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return Buffer.concat([prefix, raw]);
}

function signEd25519Base64(bytes: Buffer, privateKeyHex: string): string {
  const raw = Buffer.from(privateKeyHex.trim(), 'hex');
  if (raw.length !== 32) throw new Error('REAP3R_UPDATE_PRIVKEY_HEX must be 32-byte hex');
  const key = crypto.createPrivateKey({ key: ed25519Pkcs8FromRaw32(raw), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, bytes, key).toString('base64');
}

function resolveSignedManifestPath(os: AgentOs, arch: AgentArch, binaryPath: string): string {
  const key = `AGENT_SIGNED_MANIFEST_PATH_${os.toUpperCase()}_${arch.toUpperCase()}`;
  const fromEnv = process.env[key];
  if (fromEnv && fromEnv.trim()) return fromEnv;
  return `${binaryPath}.manifest.json`;
}

function parseSignedManifest(raw: string): ManifestInput {
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return {};
    return parsed as ManifestInput;
  } catch {
    return {};
  }
}

export async function loadAgentUpdateManifest(params: {
  os: AgentOs;
  arch: AgentArch;
  request?: any;
  strictSignature?: boolean;
}): Promise<AgentUpdateManifest> {
  const resolved = resolveBinaryPath(params.os, params.arch);
  if (!resolved) {
    throw new Error(`Unsupported os/arch: ${params.os}/${params.arch}`);
  }
  if (!fs.existsSync(resolved.filePath)) {
    throw new Error(`Agent binary not available for ${params.os}/${params.arch}`);
  }

  const strictSignature = params.strictSignature ?? (String(process.env.AGENT_UPDATE_REQUIRE_SIGNATURE || '').toLowerCase() === 'true');
  const requireAuthenticode = boolEnv(process.env.AGENT_UPDATE_REQUIRE_AUTHENTICODE, false);
  const signerThumbprint = String(process.env.AGENT_UPDATE_SIGNER_THUMBPRINT || '').trim().toUpperCase() || undefined;
  const { sha256, size } = await sha256File(resolved.filePath);
  const fileBytes = await fs.promises.readFile(resolved.filePath);
  const base = params.request ? publicBaseUrl(params.request) : (process.env.API_BASE_URL || 'http://localhost:4000');
  const fallbackDownloadUrl = `${base}/api/agent-binary/download?os=${encodeURIComponent(params.os)}&arch=${encodeURIComponent(params.arch)}`;
  const version = process.env.AGENT_VERSION || '1.0.0';

  const signedPath = resolveSignedManifestPath(params.os, params.arch, resolved.filePath);
  if (fs.existsSync(signedPath)) {
    const parsed = parseSignedManifest(await fs.promises.readFile(signedPath, 'utf8'));
    if (!parsed.sig_ed25519 || typeof parsed.sig_ed25519 !== 'string') {
      throw new Error(`Invalid signed manifest at ${signedPath}: missing sig_ed25519`);
    }
    if (!parsed.sha256 || parsed.sha256 !== sha256) {
      throw new Error(`Signed manifest sha256 mismatch at ${signedPath}`);
    }

    return {
      version: typeof parsed.version === 'string' && parsed.version.trim() ? parsed.version : version,
      sha256,
      size,
      download_url: typeof parsed.download_url === 'string' && parsed.download_url.trim() ? parsed.download_url : fallbackDownloadUrl,
      sig_ed25519: parsed.sig_ed25519,
      signed_at: typeof parsed.signed_at === 'string' ? parsed.signed_at : undefined,
      signer_thumbprint: typeof parsed.signer_thumbprint === 'string'
        ? parsed.signer_thumbprint.trim().toUpperCase()
        : signerThumbprint,
      require_authenticode: typeof parsed.require_authenticode === 'boolean'
        ? parsed.require_authenticode
        : requireAuthenticode,
      manifest_source: 'signed',
    };
  }

  const privateKeyHex = String(process.env.REAP3R_UPDATE_PRIVKEY_HEX || '').trim();
  if (privateKeyHex) {
    return {
      version,
      sha256,
      size,
      download_url: fallbackDownloadUrl,
      sig_ed25519: signEd25519Base64(fileBytes, privateKeyHex),
      signed_at: new Date().toISOString(),
      signer_thumbprint: signerThumbprint,
      require_authenticode: requireAuthenticode,
      manifest_source: 'generated_signed',
    };
  }

  if (strictSignature) {
    throw new Error(`Signed manifest required but missing for ${params.os}/${params.arch}`);
  }

  return {
    version,
    sha256,
    size,
    download_url: fallbackDownloadUrl,
    signer_thumbprint: signerThumbprint,
    require_authenticode: requireAuthenticode,
    manifest_source: 'generated',
  };
}
