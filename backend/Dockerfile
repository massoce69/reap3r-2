FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
COPY shared/package.json shared/
COPY backend/package.json backend/
RUN npm ci --workspace=shared --workspace=backend
COPY shared/ shared/
COPY backend/ backend/
COPY tsconfig.base.json ./
RUN npm -w shared run build
RUN npm -w backend run build

FROM node:22-alpine
RUN apk add --no-cache dumb-init && \
    addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder --chown=appuser:appgroup /app/package.json ./
COPY --from=builder --chown=appuser:appgroup /app/shared/package.json shared/
COPY --from=builder --chown=appuser:appgroup /app/shared/dist/ shared/dist/
COPY --from=builder --chown=appuser:appgroup /app/backend/package.json backend/
COPY --from=builder --chown=appuser:appgroup /app/backend/dist/ backend/dist/
COPY --from=builder --chown=appuser:appgroup /app/backend/src/db/migrations/ backend/dist/db/migrations/
COPY --from=builder --chown=appuser:appgroup /app/node_modules/ node_modules/
USER appuser
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/api/health || exit 1
CMD ["dumb-init", "node", "backend/dist/index.js"]
