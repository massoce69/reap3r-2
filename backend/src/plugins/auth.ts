// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Plugin (JWT + API Key + RBAC)
// ─────────────────────────────────────────────
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import jwt from '@fastify/jwt';
import { config } from '../config.js';
import { RolePermissions, Role, Permission } from '@massvision/shared';
import { validateApiKey } from '../services/apikey.service.js';
import { authenticateAccessToken } from '../services/auth-session.service.js';

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requirePermission: (permission: Permission) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    currentUser: {
      id: string;
      email: string;
      name: string;
      role: Role;
      org_id: string;
      session_id?: string;
    };
    authMethod?: 'jwt' | 'api_key';
  }
}

async function authPlugin(fastify: FastifyInstance) {
  await fastify.register(jwt, { secret: config.jwt.secret });

  fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    // Try JWT first
    const authHeader = request.headers.authorization;
    const apiKeyHeader = request.headers['x-api-key'] as string | undefined;

    // Check for API key (X-API-Key header or Bearer rp3r_...)
    const apiKeyValue = apiKeyHeader ?? (authHeader?.startsWith('Bearer rp3r_') ? authHeader.slice(7) : null);

    if (apiKeyValue?.startsWith('rp3r_')) {
      const keyData = await validateApiKey(apiKeyValue);
      if (!keyData) {
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid or expired API key' });
      }
      request.currentUser = {
        id: keyData.user_id,
        email: keyData.user_email,
        name: keyData.user_name,
        role: keyData.user_role as Role,
        org_id: keyData.org_id,
      };
      request.authMethod = 'api_key';
      return;
    }

    // Fall back to JWT
    const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!bearerToken) {
      reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid or missing token' });
      return;
    }

    const sessionUser = await authenticateAccessToken(fastify, bearerToken);
    if (!sessionUser) {
      reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Session expired or revoked' });
      return;
    }
    request.currentUser = {
      id: sessionUser.id,
      email: sessionUser.email,
      name: sessionUser.name,
      role: sessionUser.role,
      org_id: sessionUser.org_id,
      session_id: sessionUser.session_id,
    };
    request.authMethod = 'jwt';
  });

  fastify.decorate('requirePermission', (permission: Permission) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.currentUser;
      if (!user) {
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized' });
      }
      const perms = RolePermissions[user.role as Role] ?? [];
      if (!perms.includes(permission)) {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: `Missing permission: ${permission}`,
        });
      }
    };
  });
}

export default fp(authPlugin, { name: 'auth' });
