// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Plugin (JWT + RBAC)
// ─────────────────────────────────────────────
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import jwt from '@fastify/jwt';
import { config } from '../config.js';
import { RolePermissions, Role, Permission } from '@massvision/shared';

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
    };
  }
}

async function authPlugin(fastify: FastifyInstance) {
  await fastify.register(jwt, { secret: config.jwt.secret });

  fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const decoded = await request.jwtVerify();
      request.currentUser = decoded as any;
    } catch {
      reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid or missing token' });
    }
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
