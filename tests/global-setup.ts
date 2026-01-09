import { execSync } from 'child_process'
import { beforeAll, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { logger } from '../src/shared/logger/logger'

const prisma = new PrismaClient()
const schemaPath = './src/infrastructure/database/prisma/schema.prisma'

logger.info({
  from: 'test:setup',
  message: {
    status: '[TEST] ✅ Running test setup...',
    environment: `Using environment ${process.env.NODE_ENV}`,
    databaseUrl: `Using database url ${process.env.DATABASE_URL}`
  }
})

beforeAll(async () => {
  if (process.env.RUN_PRISMA_MIGRATE === 'true') {
    console.log('[TEST] Running prisma migrate reset --force')
    execSync(`npx prisma migrate reset --force --schema=${schemaPath}`, {
      stdio: 'inherit'
    })
  }
  console.log('[TEST] Running prisma db genereate')
  execSync(`npx prisma generate --schema=${schemaPath}`, {
    stdio: 'inherit'
  })

  if (process.env.RUN_PRISMA_SEED === 'true') {
    console.log('[TEST] Building project before seeding')
    execSync(`pnpm build`, { stdio: 'inherit' })

    console.log('[TEST] Running prisma db seed')
    execSync(`node ./build/infrastructure/database/seed.js`, {
      stdio: 'inherit'
    })
  }
})

afterAll(async () => {
  await prisma.$disconnect()
})
