import { z } from 'zod';
import type { FastifyReply } from 'fastify';

const uuidSchema = z.string().uuid();

/** Validate a string is a valid UUID. Sends 400 reply if invalid. Returns null on failure. */
export function parseUUID(value: string, reply: FastifyReply, name = 'id'): string | null {
  const result = uuidSchema.safeParse(value);
  if (!result.success) {
    reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: `Invalid ${name}: must be a valid UUID` });
    return null;
  }
  return result.data;
}

/** Parse and validate request body with a Zod schema. Sends 400 reply if invalid. Returns null on failure. */
export function parseBody<T>(schema: z.ZodSchema<T>, body: unknown, reply: FastifyReply): T | null {
  const result = schema.safeParse(body);
  if (!result.success) {
    reply.status(400).send({
      statusCode: 400,
      error: 'Bad Request',
      message: result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
    });
    return null;
  }
  return result.data;
}

/** Clamp a pagination limit to a maximum value */
export function clampLimit(value: unknown, defaultLimit = 25, maxLimit = 200): number {
  const n = Number(value) || defaultLimit;
  return Math.min(Math.max(n, 1), maxLimit);
}

/** Clamp a pagination offset to a minimum of 0 */
export function clampOffset(value: unknown): number {
  const n = Number(value) || 0;
  return Math.max(n, 0);
}
