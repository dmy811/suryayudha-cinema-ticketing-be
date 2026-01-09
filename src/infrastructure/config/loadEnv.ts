import dotenv from 'dotenv'

import { logger } from '@shared/logger/logger'

const env = process.env.NODE_ENV || 'development'
const envFile = `.env.${env}`

logger.info({
  from: 'config:loadEnv',
  message: `✅ Environment set to ${env} and using ${envFile} file ✅`
})
dotenv.config({ path: envFile })
