import { RateLimiterRedis } from 'rate-limiter-flexible'
import redis from './redis'

export const globalLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:global',
  points: 200, // 200 requests
  duration: 60 // per 60 seconds
})

export const loginLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:login',
  points: 5,
  duration: 60 * 5, // 5 minutes window
  blockDuration: 60 * 10 // block 10 minutes after consumed all points
})

export const burstLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:burst',
  points: 50,
  duration: 10
})
