import { PrismaClient } from '@prisma/client'
import { Mocked, vi } from 'vitest'

export const createPrismaMock = (): Mocked<PrismaClient> =>
  ({
    user: {
      findUnique: vi.fn(),
      findFirst: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn()
    }
  }) as unknown as Mocked<PrismaClient>
