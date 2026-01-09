import '../src/infrastructure/config/loadEnv'
import { execSync } from 'child_process'
import { logger } from '../src/shared/logger/logger'

const schemaPath = './src/infrastructure/database/prisma/schema.prisma'

logger.info({
  from: 'test:setup',
  message: {
    status: '[TEST] ✅ Running test setup...',
    environment: `Using environment ${process.env.NODE_ENV}`,
    databaseUrl: `Using database url ${process.env.DATABASE_URL}`
  }
})

export default async () => {
  if (process.env.RUN_PRISMA_MIGRATE === 'true') {
    console.log('[TEST] Running prisma migrate reset --force')
    execSync(`pnpm prisma migrate reset --force --schema=${schemaPath}`, {
      stdio: 'ignore'
    })
  }
  console.log('[TEST] Running prisma db genereate')
  execSync(`pnpm prisma generate --schema=${schemaPath}`, {
    stdio: 'ignore'
  })

  if (process.env.RUN_PRISMA_SEED === 'true') {
    console.log('[TEST] Running prisma db seed')
    execSync(`tsx ./src/infrastructure/database/seed.ts`, {
      stdio: 'ignore'
    })
  }
}
