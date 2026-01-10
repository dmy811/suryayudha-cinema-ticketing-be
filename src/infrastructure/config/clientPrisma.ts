import './loadEnv'
import { PrismaClient } from '@prisma/client'
import { logger } from '../../shared/logger/logger'

export const prisma = new PrismaClient({
  log: [
    {
      emit: 'event',
      level: 'query'
    },
    {
      emit: 'event',
      level: 'error'
    },
    {
      emit: 'event',
      level: 'info'
    },
    {
      emit: 'event',
      level: 'warn'
    }
  ]
})

// prisma.$on('error', (e) => {
//   logger.error({
//     from: 'client:prisma',
//     message: e.message
//   })
// })

// prisma.$on('warn', (e) => {
//   logger.warn({
//     from: 'client:prisma',
//     message: e.message
//   })
// })

// prisma.$on('info', (e) => {
//   logger.info({
//     from: 'client:prisma',
//     message: e.message
//   })
// })

// prisma.$on('query', (e) => {
//   logger.info({
//     from: 'client:prisma',
//     message: `Query: ${e.query} || Duration: ${e.duration} ms || Params: ${e.params}`
//   })
// })
