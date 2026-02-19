import { FastifyInstance } from 'fastify';
import { revealSecret } from './vault.service.js';

type InjectionMode = 'replace' | 'env';

type VaultInjectionDescriptor = {
  secret_id: string;
  mode?: InjectionMode;
  placeholder?: string;
  target_field?: string;
  env_key?: string;
};

function isObjectRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function deepCloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

function replaceAllLiteral(input: string, search: string, value: string): string {
  if (!search) return input;
  return input.split(search).join(value);
}

function deepReplaceStrings(value: unknown, placeholder: string, secretValue: string): unknown {
  if (typeof value === 'string') return replaceAllLiteral(value, placeholder, secretValue);
  if (Array.isArray(value)) return value.map((x) => deepReplaceStrings(x, placeholder, secretValue));
  if (!isObjectRecord(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) out[k] = deepReplaceStrings(v, placeholder, secretValue);
  return out;
}

function parseVaultInjection(payload: Record<string, unknown>): VaultInjectionDescriptor | null {
  const raw = payload.__vault_injection;
  if (!isObjectRecord(raw)) return null;
  if (typeof raw.secret_id !== 'string' || !raw.secret_id.trim()) return null;
  return {
    secret_id: raw.secret_id,
    mode: raw.mode === 'env' ? 'env' : 'replace',
    placeholder: typeof raw.placeholder === 'string' ? raw.placeholder : undefined,
    target_field: typeof raw.target_field === 'string' ? raw.target_field : undefined,
    env_key: typeof raw.env_key === 'string' ? raw.env_key : undefined,
  };
}

export async function hydrateJobPayloadForDispatch(
  _fastify: FastifyInstance,
  orgId: string,
  payload: unknown,
): Promise<Record<string, unknown>> {
  const base: Record<string, unknown> = isObjectRecord(payload) ? deepCloneJson(payload) : {};
  const descriptor = parseVaultInjection(base);
  if (!descriptor) return base;

  delete base.__vault_injection;
  const secretValue = await revealSecret(orgId, descriptor.secret_id);
  if (secretValue === null) {
    throw new Error(`Vault injection failed: secret not found (${descriptor.secret_id})`);
  }

  const mode: InjectionMode = descriptor.mode ?? 'replace';
  if (mode === 'env') {
    const envField = descriptor.target_field || 'env';
    const envKey = descriptor.env_key || 'REAP3R_SECRET';
    const envObj = isObjectRecord(base[envField]) ? { ...(base[envField] as Record<string, unknown>) } : {};
    envObj[envKey] = secretValue;
    base[envField] = envObj;
    return base;
  }

  const placeholder = descriptor.placeholder || '{{REAP3R_SECRET}}';
  const targetField = descriptor.target_field;
  if (targetField && typeof base[targetField] === 'string') {
    base[targetField] = replaceAllLiteral(String(base[targetField]), placeholder, secretValue);
    return base;
  }

  return deepReplaceStrings(base, placeholder, secretValue) as Record<string, unknown>;
}
