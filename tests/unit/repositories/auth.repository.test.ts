import '../../__mocks__/mockRedis'
import { beforeEach, describe, it, vi, expect } from 'vitest'

vi.mock('../../../src/shared/helpers/checkExistingRow')
vi.mock('../../../src/infrastructure/config/imagekit.config', () => ({
  uploadImageToImageKit: vi.fn()
}))
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
import { createPrismaMock } from '../../__mocks__/mockPrisma'
import { BadRequestException } from '../../../src/shared/error-handling/exceptions/bad-request.exception'
import { NotFoundException } from '../../../src/shared/error-handling/exceptions/not-found.exception'
import { number, string } from 'zod'

describe('AuthRepository (unit)', () => {
  let authRepositoryPrisma: AuthRepositoryPrisma
  let prismaMock: ReturnType<typeof createPrismaMock>

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
    prismaMock = createPrismaMock()
    authRepositoryPrisma = new AuthRepositoryPrisma(prismaMock)
  })

  it('register -> should register user successfully', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    vi.mocked(prismaMock.user.create).mockResolvedValue({
      id: expect.any(Number),
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: expect.any(String),
      is_verified: false,
      verification_token: expect.any(String),
      verification_token_expires_at: expect.any(Date),
      reset_password_token: expect.any(String),
      reset_password_token_expires_at: expect.any(Date),
      profile_url: expect.any(String),
      provider: expect.any(String),
      providerId: expect.any(String),
      created_at: expect.any(Date),
      updated_at: expect.any(Date)
    } as any)

    const result = await authRepositoryPrisma.register({
      name: 'Test User',
      email: 'test@mail.com',
      password: 'password',
      passwordConfirmation: 'password',
      verification_token: 'token'
    })
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.create).toHaveBeenCalled()
    expect(sendEmail).toHaveBeenCalledWith({
      email: 'test@mail.com',
      subject: 'Verifikasi Akun Surya Yudha Cinema Anda',
      html: expect.any(String)
    })
    expect(result).toEqual(
      expect.objectContaining({
        id: expect.any(Number),
        name: 'Test User',
        role: 'user',
        email: 'test@mail.com',
        password: expect.any(String),
        is_verified: false,
        verification_token: expect.any(String),
        verification_token_expires_at: expect.any(Date),
        reset_password_token: expect.any(String),
        reset_password_token_expires_at: expect.any(Date),
        profile_url: expect.any(String),
        provider: expect.any(String),
        providerId: expect.any(String),
        created_at: expect.any(Date),
        updated_at: expect.any(Date)
      })
    )
  })

  it('register -> should throw error if email already registered', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({} as any)

    await expect(
      authRepositoryPrisma.register({
        email: 'test@mail.com'
      } as any)
    ).rejects.toBeInstanceOf(BadRequestException)
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.create).not.toHaveBeenCalled()

    // or like this
    // try {
    //   await authRepositoryPrisma.register({
    //     email: 'test@mail.com'
    //   })
    // } catch (error) {
    //   expect(error).toBeInstanceOf(BadRequestException)
    // }
  })

  it('resend verification link -> should send verification link successfully', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({} as any)
    vi.mocked(prismaMock.user.update).mockResolvedValue({} as any)

    await authRepositoryPrisma.resendVerificationLink('sample@gmail.com')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).toHaveBeenCalled()
    expect(generateVerificationToken).toHaveBeenCalled()
    expect(sendEmail).toHaveBeenCalledWith({
      email: 'sample@gmail.com',
      subject: 'Link Verifikasi Akun Baru Anda',
      html: expect.any(String)
    })
  })

  it('resend verification link -> should throw error if user not found', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    await expect(
      authRepositoryPrisma.resendVerificationLink('sample@gmail.com')
    ).rejects.toBeInstanceOf(NotFoundException)
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('verify email -> should verify email successfully', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      verification_token: 'token',
      is_verified: false,
      verification_token_expires_at: new Date(Date.now() + 60 * 60 * 1000)
    } as any)
    vi.mocked(prismaMock.user.update).mockResolvedValue({} as any)

    await authRepositoryPrisma.verifyEmail('token', 'sample@gmail.com')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).toHaveBeenCalled()
  })

  it('verify email -> should throw error if user not found', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    await expect(
      authRepositoryPrisma.verifyEmail('token', 'sample@gmail.com')
    ).rejects.toBeInstanceOf(NotFoundException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('verify email -> should throw error if verification token is wrong', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      verification_token: 'wrong token'
    } as any)

    await expect(
      authRepositoryPrisma.verifyEmail('token', 'sample@gmail.com')
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('verify email -> should throw error if email user already verified', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      is_verified: true
    } as any)

    await expect(
      authRepositoryPrisma.verifyEmail('token', 'sample@gmail.com')
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('verify email -> should throw error if verification token is expired', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      verification_token_expires_at: new Date(Date.now() - 60 * 60 * 1000) // 1 hour ago
    } as any)

    await expect(
      authRepositoryPrisma.verifyEmail('token', 'sample@gmail.com')
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('login -> should login user and return tokens', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: '1',
      email: 'test@mail.com',
      password: 'hashed',
      role: 'user',
      name: 'Test'
    } as any)

    const result = await authRepositoryPrisma.login({
      email: 'test@mail.com',
      password: 'password'
    })

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalledWith('hashed', 'password')
    expect(signJwt).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        id: expect.any(String),
        name: expect.any(String),
        email: expect.any(String),
        role: 'user'
      }),
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )

    expect(signJwt).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        id: expect.any(String),
        jti: expect.any(String),
        name: expect.any(String),
        email: expect.any(String),
        role: 'user'
      }),
      'REFRESH_TOKEN_PRIVATE_KEY',
      { expiresIn: '7d' }
    )
    expect(setCache).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.any(Number)
    )
    expect(result.accessToken).toBeDefined()
    expect(result.refreshToken).toBeDefined()
    expect(result).toHaveProperty('accessToken')
    expect(result).toHaveProperty('refreshToken')
    expect(result).toEqual({
      accessToken: expect.any(String),
      refreshToken: expect.any(String)
    })
    expect(result).toStrictEqual({
      accessToken: 'jwt-token',
      refreshToken: 'jwt-token'
    })
    expect(result).toEqual(
      expect.objectContaining({
        accessToken: expect.any(String),
        refreshToken: expect.any(String)
      })
    )
  })

  it('login -> should throw error if user are not found', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    await expect(
      authRepositoryPrisma.login({ email: 'test@mail.com', password: 'wrong' })
    ).rejects.toBeInstanceOf(NotFoundException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
    expect(verifyPassword).not.toHaveBeenCalled()
    expect(signJwt).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  it('login -> should throw error if user role is admin, because this route only for user', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: '1',
      email: 'test@mail.com',
      password: 'hashed',
      role: 'admin',
      name: 'Test'
    } as any)

    await expect(
      authRepositoryPrisma.login({ email: 'test@mail.com', password: 'wrong' })
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
    expect(verifyPassword).not.toHaveBeenCalled()
    expect(signJwt).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  it('login -> should throw error if password does not match', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: '1',
      email: 'test@mail.com',
      password: 'hashed',
      role: 'user',
      name: 'Test'
    } as any)
    vi.mocked(verifyPassword).mockResolvedValue(false)

    await expect(
      authRepositoryPrisma.login({ email: 'test@mail.com', password: 'wrong' })
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalled()
    expect(signJwt).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  // login admin
  it('login admin -> should login admin and return tokens', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: '1',
      email: 'test@mail.com',
      password: 'hashed',
      role: 'admin',
      name: 'Test'
    } as any)

    const result = await authRepositoryPrisma.loginAdmin({
      email: 'test@mail.com',
      password: 'password'
    })

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalledWith('hashed', 'password')
    expect(signJwt).toHaveBeenCalled()
    expect(signJwt).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        id: expect.any(String),
        name: expect.any(String),
        email: expect.any(String),
        role: 'admin'
      }),
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )

    expect(signJwt).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        id: expect.any(String),
        jti: expect.any(String),
        name: expect.any(String),
        email: expect.any(String),
        role: 'admin'
      }),
      'REFRESH_TOKEN_PRIVATE_KEY',
      { expiresIn: '7d' }
    )
    expect(setCache).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.any(Number)
    )
    expect(result.accessToken).toBeDefined()
    expect(result.refreshToken).toBeDefined()
    expect(result).toHaveProperty('accessToken')
    expect(result).toHaveProperty('refreshToken')
    expect(result).toEqual({
      accessToken: expect.any(String),
      refreshToken: expect.any(String)
    })
    expect(result).toStrictEqual({
      accessToken: 'jwt-token',
      refreshToken: 'jwt-token'
    })
    expect(result).toEqual(
      expect.objectContaining({
        accessToken: expect.any(String),
        refreshToken: expect.any(String)
      })
    )
  })

  it('login admin -> should throw error if user are not found', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    await expect(
      authRepositoryPrisma.loginAdmin({ email: 'test@mail.com', password: 'wrong' })
    ).rejects.toBeInstanceOf(NotFoundException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
    expect(verifyPassword).not.toHaveBeenCalled()
    expect(signJwt).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  it('login admin -> should throw error if user role is user, because this route only for admin', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: '1',
      email: 'test@mail.com',
      password: 'hashed',
      role: 'user',
      name: 'Test'
    } as any)

    await expect(
      authRepositoryPrisma.loginAdmin({ email: 'test@mail.com', password: 'wrong' })
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
    expect(verifyPassword).not.toHaveBeenCalled()
    expect(signJwt).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  it('login admin -> should throw error if password does not match', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: '1',
      email: 'test@mail.com',
      password: 'hashed',
      role: 'admin',
      name: 'Test'
    } as any)
    vi.mocked(verifyPassword).mockResolvedValue(false)

    await expect(
      authRepositoryPrisma.loginAdmin({ email: 'test@mail.com', password: 'wrong' })
    ).rejects.toBeInstanceOf(BadRequestException)

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
    expect(signJwt).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  it('refresh token -> should successfully rotate refresh token', async () => {
    vi.mocked(redis.get).mockResolvedValue({} as any)
    vi.mocked(verifyJwtToken).mockReturnValue({
      id: 1,
      name: 'name',
      email: 'email@gmail.com',
      role: 'user',
      iat: '93812',
      exp: '1312',
      jti: 'jti'
    })
    const result = await authRepositoryPrisma.refreshToken('refresh token')

    // I know its over assertion. its just for learning
    expect(verifyJwtToken).toHaveBeenCalled()
    expect(verifyJwtToken).toHaveBeenCalledWith('refresh token', expect.any(String))
    expect(redis.get).toHaveBeenCalled()
    expect(redis.get).toHaveBeenCalledWith('refresh-token:jti')
    expect(redis.get).toHaveBeenCalledWith(expect.stringContaining('refresh-token'))
    expect(redis.del).toHaveBeenCalled()
    expect(redis.del).toHaveBeenCalledTimes(1)
    expect(signJwt).toHaveBeenCalled()
    expect(signJwt).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        id: expect.any(Number),
        name: expect.any(String),
        email: expect.any(String),
        role: expect.any(String)
      }),
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )

    expect(signJwt).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        id: expect.any(Number),
        jti: expect.any(String),
        name: expect.any(String),
        email: expect.any(String),
        role: expect.any(String)
      }),
      'REFRESH_TOKEN_PRIVATE_KEY',
      { expiresIn: '7d' }
    )
    expect(setCache).toHaveBeenCalled()
    expect(setCache).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.any(Number)
    )
    expect(result.newAccessToken).toBeDefined()
    expect(result.newRefreshToken).toBeDefined()
    expect(result).toHaveProperty('newAccessToken')
    expect(result).toHaveProperty('newRefreshToken')
    expect(result).toEqual({
      newAccessToken: expect.any(String),
      newRefreshToken: expect.any(String)
    })
    expect(result).toStrictEqual({
      newAccessToken: 'jwt-token',
      newRefreshToken: 'jwt-token'
    })
    expect(result).toEqual(
      expect.objectContaining({
        newAccessToken: expect.any(String),
        newRefreshToken: expect.any(String)
      })
    )
  })
})
