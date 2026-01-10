import { Request, Response, NextFunction } from 'express'
import { RateLimiterRedis } from 'rate-limiter-flexible'
import { logger } from '../logger/logger'

export function createRateLimiter(
  limiter: RateLimiterRedis,
  keyExtractor: (req: Request) => string = (req) => `ip:${req.ip}`,
  { failOpen = true } = {}
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const key = keyExtractor(req)
    try {
      await limiter.consume(key)
      return next()
    } catch (error: any) {
      const retrySecs = Math.ceil(error.msBeforeNext / 1000) || 1
      res.setHeader('Retry-After', String(retrySecs))

      logger.warn('Rate limit exceeded', {
        key,
        route: req.path,
        method: req.method,
        msBeforeNext: error.msBeforeNext,
        consumedPoints: error.consumedPoints
      })

      return res.status(429).json({ success: false, message: 'Too many requests' })
    }
  }
}
