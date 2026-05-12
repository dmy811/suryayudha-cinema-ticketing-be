import { PrismaClient } from '@prisma/client'
import { logger } from '@/shared/logger/logger'

export const tableName = 'Users'

export default async function seed(prisma: PrismaClient) {
  await prisma.user.create({
    data: {
      name: 'Joker',
      email: 'joker@gmail.com',
      role: 'admin',
      is_verified: true,
      password: process.env.ADMIN_PASSWORD as string
    }
  })
  logger.info({
    from: 'seed:admin',
    message: 'Admin seeded successfully ✅'
  })
}
