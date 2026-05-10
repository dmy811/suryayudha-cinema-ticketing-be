import '@infrastructure/config/loadEnv'
import { logger } from '@shared/logger/logger'
import { Routes } from '../applications/routes/routes'
import App from '../applications/app'
async function bootstrap() {
  try {
    const routes = new Routes()
    const app = new App(routes)
    await app.start()
    logger.info({
      from: 'index:bootstrap',
      message: '✅ Server successfully started ✅'
    })
  } catch (error) {
    logger.error({
      from: 'index:bootstrap',
      message: '❌ Failed to start server ❌',
      error
    })
    console.log(error)
    process.exit(1)
  }
}

bootstrap()
