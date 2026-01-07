import '../../__mocks__/mockRedis'
import { beforeEach, describe, it, vi, expect } from 'vitest'

vi.mock('../../../src/shared/helpers/checkExistingRow')
vi.mock('../../../src/infrastructure/config/imagekit.config')
vi.mock('../../../src/infrastructure/config/nodemailer')
vi.mock('../../../src/shared/helpers/generateVerificationToken')
vi.mock('../../../src/shared/helpers/passwordEncrypt')
vi.mock('../../../src/infrastructure/config/jwt')
vi.mock('../../../src/shared/logger/logger')
vi.mock('../../../src/infrastructure/cache/setCache')

import { checkExists } from '../../../src/shared/helpers/checkExistingRow'
import { uploadImageToImageKit } from '../../../src/infrastructure/config/imagekit.config'
import { sendEmail } from '../../../src/infrastructure/config/nodemailer'
import { generateVerificationToken } from '../../../src/shared/helpers/generateVerificationToken'
import { hashPassword, verifyPassword } from '../../../src/shared/helpers/passwordEncrypt'
import { signJwt, verifyJwtToken } from '../../../src/infrastructure/config/jwt'
import { logger } from '../../../src/shared/logger/logger'
import { setCache } from '../../../src/infrastructure/cache/setCache'
import redis from '../../../src/infrastructure/config/redis'
import { AuthRepositoryPrisma } from '../../../src/infrastructure/repositories/AuthRepositoryPrisma'

describe('AuthRepository (unit)', () => {
  let authRepositoryPrisma: AuthRepositoryPrisma

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(checkExists).mockResolvedValue(undefined)
    vi.mocked(uploadImageToImageKit).mockResolvedValue({ url: 'url', fileId: 'field' })
    vi.mocked(sendEmail).mockResolvedValue(undefined)
    vi.mocked(generateVerificationToken).mockReturnValue('verif-token')
    vi.mocked(hashPassword).mockResolvedValue('hash-password')
    vi.mocked(verifyPassword).mockResolvedValue(true)
    vi.mocked(signJwt).mockReturnValue('jwt-token')
    vi.mocked(verifyJwtToken).mockReturnValue({})
    vi.mocked(logger.info).mockReturnValue(logger)
    vi.mocked(logger.error).mockReturnValue(logger)
    vi.mocked(logger.warn).mockReturnValue(logger)
    vi.mocked(setCache).mockResolvedValue(undefined)
  })
})
