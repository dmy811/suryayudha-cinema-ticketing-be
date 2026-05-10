import dotenv from 'dotenv'

import { logger } from '@shared/logger/logger'

dotenv.config()

const env = process.env.NODE_ENV || 'development'

logger.info({
  from: 'config:loadEnv',
  message: `✅ Environment loaded (.env) | NODE_ENV=${env} ✅`
})
