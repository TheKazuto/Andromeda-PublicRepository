# --- Build stage ---
FROM node:22-alpine AS builder

WORKDIR /app

# .npmrc carries `legacy-peer-deps=true` — required while
# @encrypt.xyz/pre-alpha-solana-client@0.1.x declares `typescript: '^5'` as a
# peer dep (we run TS 6). Drop it once that client relaxes the constraint.
COPY package.json package-lock.json* .npmrc ./
RUN npm ci || npm install

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

# --- Runtime stage ---
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY package.json package-lock.json* .npmrc ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY --from=builder /app/dist ./dist

EXPOSE 3010

USER node

CMD ["node", "dist/server.js"]
