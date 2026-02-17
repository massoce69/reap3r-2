FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
COPY shared/package.json shared/
COPY frontend/package.json frontend/
RUN npm ci --workspace=shared --workspace=frontend
COPY shared/ shared/
COPY frontend/ frontend/
COPY tsconfig.base.json ./
RUN npm -w shared run build
RUN npm -w frontend run build

FROM node:22-alpine
RUN apk add --no-cache dumb-init && \
    addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder --chown=appuser:appgroup /app/frontend/.next/standalone ./
COPY --from=builder --chown=appuser:appgroup /app/frontend/.next/static ./.next/static
COPY --from=builder --chown=appuser:appgroup /app/frontend/public ./public
USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1
CMD ["dumb-init", "node", "server.js"]
