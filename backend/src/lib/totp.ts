import crypto from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(input: string): Buffer {
  const normalized = input.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  if (!normalized) throw new Error('Empty secret');

  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (const char of normalized) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }

  return Buffer.from(out);
}

function secretToBuffer(secret: string): Buffer {
  const normalized = (secret || '').trim();
  if (!normalized) throw new Error('Empty secret');
  if (/^[0-9a-f]+$/i.test(normalized) && normalized.length % 2 === 0) {
    return Buffer.from(normalized, 'hex');
  }
  return decodeBase32(normalized);
}

export function generateTOTP(secret: string, window = 0): string {
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30) + window;
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter & 0xffffffff, 4);

  const key = secretToBuffer(secret);
  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % 1000000;
  return code.toString().padStart(6, '0');
}

export function verifyTOTP(secret: string, code: string): boolean {
  const normalizedCode = String(code || '').trim();
  if (!/^\d{6}$/.test(normalizedCode)) return false;
  try {
    for (let w = -1; w <= 1; w++) {
      if (generateTOTP(secret, w) === normalizedCode) return true;
    }
    return false;
  } catch {
    return false;
  }
}
