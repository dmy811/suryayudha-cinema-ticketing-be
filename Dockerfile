# =========================
# Builder Stage
# =========================
FROM node:20-slim AS builder

RUN corepack enable

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssl \
    libc6 \
    libgcc-s1 \
    libstdc++6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm prisma:generate:prod

RUN pnpm build

# =========================
# Production Stage
# =========================

FROM node:20-slim AS production

RUN corepack enable

WORKDIR /app

RUN apt-get update && apt-get install -y \
    openssl \
    libc6 \
    libgcc-s1 \
    libstdc++6 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY package.json pnpm-lock.yaml ./

RUN pnpm install --prod --frozen-lockfile

COPY --from=builder /app/build ./build

COPY --from=builder /app/src/infrastructure/database/prisma ./src/infrastructure/database/prisma

RUN pnpm prisma generate --schema=./src/infrastructure/database/prisma/schema.prisma

RUN useradd -m appuser \
    && mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

CMD ["sh", "-c", "pnpm prisma:migrate:prod && node build/server/index.js"]