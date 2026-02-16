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
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/package.json ./
COPY --from=builder /app/shared/package.json shared/
COPY --from=builder /app/shared/dist/ shared/dist/
COPY --from=builder /app/backend/package.json backend/
COPY --from=builder /app/backend/dist/ backend/dist/
COPY --from=builder /app/backend/src/db/migrations/ backend/dist/db/migrations/
COPY --from=builder /app/node_modules/ node_modules/
EXPOSE 4000
CMD ["node", "backend/dist/index.js"]
