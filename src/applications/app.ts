import '@infrastructure/config/oauthPassportStrategy'
import express, { Application } from 'express'
import cors from 'cors'
import morgan from 'morgan'
import compression from 'compression'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import passport from 'passport'
import { cleanEnv, str, num } from 'envalid'
import { logger } from '@shared/logger/logger'
import { requestLogger } from '@shared/logger/request-logger.middleware'
import { prisma } from '@infrastructure/config/clientPrisma'
import { errorMiddleware } from '@shared/error-handling/middleware/error.middleware'
import { IApp } from '@infrastructure/types/app.type'
import { IRoutes } from '@infrastructure/types/route.type'
import { scheduleAllJobs } from '@infrastructure/cron-jobs'
import { setupSwagger } from '@src/docs/swagger'

class App implements IApp {
  private app: Application
  private server?: ReturnType<Application['listen']>
  private readonly isProduction: boolean
  private routes: IRoutes

  constructor(routes: IRoutes) {
    this.app = express()
    this.routes = routes
    this.isProduction = process.env.NODE_ENV === 'production'

    this.validateEnvironment()
    this.initializeMiddlewares()
    this.initializeRoutes()
    this.initializeErrorHandling()
    this.initializeHealthCheck()
  }

  private validateEnvironment(): void {
    cleanEnv(process.env, {
      PORT: num({ default: 3000 }),
      NODE_ENV: str({ choices: ['development', 'production', 'test'], default: 'development' }),
      DATABASE_URL: str(),
      ACCESS_TOKEN_PRIVATE_KEY: str(),
      ACCESS_TOKEN_PUBLIC_KEY: str(),
      REFRESH_TOKEN_PRIVATE_KEY: str(),
      REFRESH_TOKEN_PUBLIC_KEY: str(),
      CORS_ORIGIN: str(),
      IMAGEKIT_PUBLIC_KEY: str(),
      IMAGEKIT_PRIVATE_KEY: str(),
      IMAGEKIT_URL_ENDPOINT: str(),
      APP_PASSWORD: str(),
      USER_EMAIL: str(),
      MIDTRANS_SERVER_KEY: str(),
      MIDTRANS_CLIENT_KEY: str(),
      GOOGLE_CLIENT_ID: str(),
      GOOGLE_CLIENT_SECRET: str(),
      FACEBOOK_CLIENT_ID: str(),
      FACEBOOK_CLIENT_SECRET: str(),
      GOOGLE_CALLBACK_URL: str(),
      FACEBOOK_CALLBACK_URL: str(),
      REDIS_PORT: num(),
      REDIS_HOST: str(),
      REDIS_PASSWORD: str(),
      LOG_DIRECTORY: str(),
      CLIENT_URL: str()
    })
  }

  private initializeMiddlewares(): void {
    this.app.use(helmet())
    this.app.use(
      cors({
        origin: process.env.CORS_ORIGIN,
        credentials: true,
        methods: ['GET', 'Head', 'POST', 'PUT', 'PATCH', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
      })
    )
    this.app.use(passport.initialize())
    this.app.use(morgan(this.isProduction ? 'combined' : 'dev'))
    this.app.use(compression())
    this.app.use(express.json())
    this.app.use(requestLogger)
    this.app.use(cookieParser())
    this.app.use(express.urlencoded({ extended: true }))
  }

  private initializeRoutes(): void {
    setupSwagger(this.app)
    this.app.use('/api', this.routes.getRoutes())
  }

  private initializeErrorHandling(): void {
    this.app.use(errorMiddleware)
  }

  private initializeHealthCheck(): void {
    this.app.get('/health', (_: express.Request, res: express.Response) => {
      res.status(200).json({ status: 'SERVER OK' })
    })
    this.app.get('/health/db', async (_, res) => {
      try {
        await prisma.$queryRaw`SELECT 1`
        res.json({ database: 'DATABASE OK' })
      } catch (error) {
        res.status(500).json({ database: 'Unhealthy' })
      }
    })
  }

  public async start(): Promise<void> {
    try {
      await prisma.$connect()
      logger.info({
        from: 'application:start',
        message: '✅ Database with prisma connected ✅'
      })
      this.server = this.app.listen(process.env.PORT, () => {
        logger.info({
          from: 'application:start',
          message: `✅ App is listening on port ${process.env.PORT} ✅`
        })
        scheduleAllJobs()
      })
      this.setupGracefulShutdown()
    } catch (error) {
      logger.error({
        from: 'application:start',
        message: '❌ Failed to start server ❌',
        error
      })
      process.exit(1)
    }
  }

  public getAppInstance(): Application {
    return this.app
  }

  private setupGracefulShutdown(): void {
    const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGQUIT']

    const shutdown = async (signal: NodeJS.Signals) => {
      logger.warn({
        from: 'application:shutdown',
        message: `Received ${signal}, shutting down...`
      })

      try {
        await prisma.$disconnect()
        if (this.server) this.server.close()
        logger.info({
          from: 'application:shutdown',
          message: '✅ Server shut down gracefully ✅'
        })
        process.exit(0)
      } catch (error) {
        logger.error({
          from: 'application:shutdown',
          message: '❌ Failed to shut down server ❌',
          error
        })
        process.exit(1)
      }
    }
    signals.forEach((signal) => process.on(signal, shutdown))
    process.on('unhandledRejection', (reason) => {
      logger.error({
        from: 'application:unhandledRejection',
        message: '❌ Unhandled Rejection ❌',
        reason
      })
      shutdown('unhandledRejection' as NodeJS.Signals)
    })
    process.on('uncaughtException', (error) => {
      logger.error({
        from: 'application:uncaughtException',
        message: '❌ Uncaught Exception ❌',
        error
      })
      shutdown('uncaughtException' as NodeJS.Signals)
    })
  }
}

export default App
