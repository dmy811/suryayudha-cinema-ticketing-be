import '../__mocks__/mockRedis'
import { describe, expect, it, beforeEach, vi } from 'vitest'
import cookieParser from 'cookie-parser'

vi.mock('../../src/shared/helpers/generateVerificationToken')
vi.mock('../../src/shared/helpers/setCookies')
vi.mock('../../src/infrastructure/config/jwt')
vi.mock('../../src/shared/logger/logger')
vi.mock('../../src/shared/helpers/clearCookies')
vi.mock('../../src/infrastructure/config/imagekit.config', () => ({
  uploadImageToImageKit: vi.fn()
}))
vi.mock('../../src/shared/helpers/checkExistingRow', () => ({
  checkExists: vi.fn()
}))

vi.mock('../../src/infrastructure/config/nodemailer')
vi.mock('../../src/shared/helpers/passwordEncrypt')
vi.mock('../../src/infrastructure/cache/setCache')
vi.mock('passport', () => {
  return {
    default: {
      initialize: () => (req: any, res: any, next: any) => next(),
      authenticate: () => (req: any, res: any, next: any) => {
        req.user = {
          id: 1,
          name: 'Test User',
          email: 'test@gmail.com',
          role: 'user'
        }
        next()
      }
    }
  }
})

import supertest from 'supertest'
import express, { Request, Response, NextFunction } from 'express'
import { AuthController } from '../../src/applications/modules/Auth/auth.controller'
import { AuthService } from '../../src/applications/modules/Auth/auth.service'
import { generateVerificationToken } from '../../src/shared/helpers/generateVerificationToken'
import { signJwt, verifyJwtToken } from '../../src/infrastructure/config/jwt'
import { logger } from '../../src/shared/logger/logger'
import { setAccessToken, setRefreshToken } from '../../src/shared/helpers/setCookies'
import { setCache } from '../../src/infrastructure/cache/setCache'
import { clearAuthCookies } from '../../src/shared/helpers/clearCookies'
import { AuthRepositoryPrisma } from '../../src/infrastructure/repositories/AuthRepositoryPrisma'
import { createPrismaMock } from '../__mocks__/mockPrisma'
import redis from '../../src/infrastructure/config/redis'
import { hashPassword, verifyPassword } from '../../src/shared/helpers/passwordEncrypt'
import { checkExists } from '../../src/shared/helpers/checkExistingRow'
import { uploadImageToImageKit } from '../../src/infrastructure/config/imagekit.config'
import { sendEmail } from '../../src/infrastructure/config/nodemailer'
import { BadRequestException } from '../../src/shared/error-handling/exceptions/bad-request.exception'
import { HttpException } from '../../src/shared/error-handling/exceptions/http.exception'
import { ZodError } from 'zod'
import { NotFoundException } from '../../src/shared/error-handling/exceptions/not-found.exception'

describe('Auth Controller Routes', () => {
  let app: express.Application
  let authController: AuthController
  let authService: AuthService
  let authRepositoryPrisma: AuthRepositoryPrisma
  let prismaMock: ReturnType<typeof createPrismaMock>

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(setAccessToken).mockReturnValue(undefined)
    vi.mocked(setRefreshToken).mockReturnValue(undefined)
    vi.mocked(clearAuthCookies).mockReturnValue(undefined)
    vi.mocked(signJwt).mockReturnValue('token')
    vi.mocked(verifyJwtToken).mockReturnValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      iat: '31312',
      exp: '2312312',
      jti: 'alskjdhasdjsakaj'
    })
    vi.mocked(uploadImageToImageKit).mockResolvedValue({ url: 'url', fileId: 'field' })
    vi.mocked(sendEmail).mockResolvedValue(undefined)
    vi.mocked(generateVerificationToken).mockReturnValue('verif-token')
    vi.mocked(hashPassword).mockResolvedValue('hash-password')
    vi.mocked(verifyPassword).mockResolvedValue(true)
    vi.mocked(logger.info).mockReturnValue(logger)
    vi.mocked(logger.error).mockReturnValue(logger)
    vi.mocked(logger.warn).mockReturnValue(logger)
    vi.mocked(setCache).mockResolvedValue(undefined)

    app = express()
    app.use(express.json())
    prismaMock = createPrismaMock()
    authRepositoryPrisma = new AuthRepositoryPrisma(prismaMock)
    authService = new AuthService(authRepositoryPrisma)
    authController = new AuthController(authService)
    app.use(cookieParser())
    app.use('/api/v1/auth', authController.getRoutes())
    app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof HttpException) {
        const statusCode = err.statusCode || 500
        return res.status(statusCode).json(err.serialize())
      }

      if (err instanceof ZodError) {
        const messages = err.errors.map((e) => e.message).join(', ')
        return res.status(400).json({
          success: false,
          statusCode: 400,
          errorCode: 'BAD_REQUEST',
          message: messages,
          timeStamp: new Date()
        })
      }
      res.status(err.status || 500).json({ success: false, message: err.message || String(err) })
    })
  })

  it('POST /register -> should succssfully registered a user', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    vi.mocked(prismaMock.user.create).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const requestBody = {
      name: 'dims',
      email: 'sample@gmail.com',
      password: '00000000',
      passwordConfirmation: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody).expect(201)
    expect(res.statusCode).toBe(201)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe(
      'Berhasil register dan verifikasi link telah dikirim ke email anda!, silahkan cek email untuk verifikasi'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.create).toHaveBeenCalled()
    expect(generateVerificationToken).toHaveBeenCalled()
    expect(hashPassword).toHaveBeenCalledWith('00000000')
    expect(sendEmail).toHaveBeenCalledWith({
      email: 'sample@gmail.com',
      subject: 'Verifikasi Akun Surya Yudha Cinema Anda',
      html: expect.any(String)
    })
  })

  it('POST /register -> failed register because email already exists', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const requestBody = {
      name: 'dims',
      email: 'sample@gmail.com',
      password: '00000000',
      passwordConfirmation: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.statusCode).toBe(400)
    expect(res.body.message).toBe('Error saat membuat user: Email sample@gmail.com sudah terdaftar')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))

    expect(generateVerificationToken).toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.create).not.toHaveBeenCalled()
    expect(hashPassword).not.toHaveBeenCalled()
    expect(sendEmail).not.toHaveBeenCalled()
  })

  it('POST /register -> failed register because got zod validation error (name is required)', async () => {
    const requestBody = {
      //   name: 'dims',
      email: 'sample@gmail.com',
      password: '00000000',
      passwordConfirmation: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.statusCode).toBe(400)
    expect(res.body.message).toBe('Error saat membuat user: Nama harus diisi')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))

    expect(generateVerificationToken).toHaveBeenCalled()
  })

  it('POST /register -> failed register because got zod validation error (password character minimum is 8)', async () => {
    const requestBody = {
      name: 'dims',
      email: 'sample@gmail.com',
      password: '000',
      passwordConfirmation: '000'
    }

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.statusCode).toBe(400)
    expect(res.body.message).toBe('Error saat membuat user: Password minimal 8 karakter')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))

    expect(generateVerificationToken).toHaveBeenCalled()
  })

  it('POST /resend-verification-token -> successfully send verification token to email user', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app)
      .post('/api/v1/auth/resend-verification-token')
      .send({ email: 'sample@gmail.com' })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Link verifikasi berhasil dikirim ulang')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(generateVerificationToken).toHaveBeenCalled()
    expect(sendEmail).toHaveBeenCalledWith({
      email: 'sample@gmail.com',
      subject: 'Link Verifikasi Akun Baru Anda',
      html: expect.any(String)
    })
  })

  it('POST /resend-verification-token -> failed because user email not founded', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    const res = await supertest(app)
      .post('/api/v1/auth/resend-verification-token')
      .send({ email: 'sample@gmail.com' })
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat mengirim email verifikasi: User dengan email sample@gmail.com tidak ditemukan'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(generateVerificationToken).not.toHaveBeenCalled()
    expect(sendEmail).not.toHaveBeenCalled()
  })

  it('GET /verify-email -> successfully verify email', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: '978241',
      verification_token_expires_at: new Date(Date.now() + 60 * 60 * 1000),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app).get(
      '/api/v1/auth/verify-email?token=978241&email=sample@gmail.com'
    )

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Email berhasil diverifikasi')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).toHaveBeenCalled()
  })

  it('GET /verify-email -> failed because user email not founded', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)

    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat verifikasi email: User dengan email sample@gmail.com tidak ditemukan'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('GET /verify-email -> failed because token is wrong', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'wrong',
      verification_token_expires_at: new Date(Date.now() + 60 * 60 * 1000),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Token verifikasi salah')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('GET /verify-email -> failed because email already verified', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: true,
      verification_token: '978241',
      verification_token_expires_at: new Date(Date.now() + 60 * 60 * 1000),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Email sudah terverifikasi')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  it('GET /verify-email -> failed because verification token is expired', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: '978241',
      verification_token_expires_at: new Date(Date.now() - 60 * 60 * 1000),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Token verifikasi sudah kadaluarsa')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  // login
  it('POST /login -> successfully login', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(200)
    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Login berhasil')

    expect(setAccessToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalledWith('hashed', '00000000')
    expect(signJwt).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        id: 1,
        name: 'dims',
        email: 'sample@gmail.com',
        role: 'user'
      }),
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )

    expect(signJwt).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        jti: expect.any(String),
        id: 1,
        name: 'dims',
        email: 'sample@gmail.com',
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
  })

  it('POST /login -> failed to login because required fields not provided', async () => {
    const requestBody = {
      email: 'sample@gmail.com'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password harus diisi')

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
  })

  it('POST /login -> failed to login because email not exists in database', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(404)
    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat login: User dengan email sample@gmail.com tidak ditemukan'
    )

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /login -> failed to login if user role is admin, because this route only for user', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'admin',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Login ini hanya untuk user')

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /login -> failed to login because password doenst match', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    vi.mocked(verifyPassword).mockResolvedValue(false)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password salah')

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalledWith('hashed', '00000000')
  })

  it('POST /refresh -> successfully refresh and rotate token', async () => {
    vi.mocked(redis.get).mockResolvedValue({} as any)
    const mockRefreshToken = 'khl433k4j23lkj'
    const res = await supertest(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refreshToken=${mockRefreshToken}`])
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Refresh token berhasil')

    expect(setAccessToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalled()
    expect(verifyJwtToken).toHaveBeenCalledWith('khl433k4j23lkj', 'REFRESH_TOKEN_PUBLIC_KEY')
    expect(redis.get).toHaveBeenCalledWith(expect.stringContaining('refresh-token'))
    expect(redis.del).toHaveBeenCalledTimes(1)
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
    expect(setCache).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.any(Number)
    )
  })

  it('POST /refresh -> should throw error if refresh token doesnt exists in redis', async () => {
    vi.mocked(redis.get).mockResolvedValue(null)
    const mockRefreshToken = 'khl433k4j23lkj'
    const res = await supertest(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refreshToken=${mockRefreshToken}`])
      .expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat refresh token: Refresh token di verifikasi oleh redis, akses ditolak karena refresh token tidak ada atau tidak valid'
    )

    expect(signJwt).not.toHaveBeenCalled()
    expect(redis.del).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
  })

  it('POST /refresh -> should throw error if refresh token doesnt exists in cookies', async () => {
    const res = await supertest(app).post('/api/v1/auth/refresh').expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat refresh token: Refresh token tidak ditemukan di cookies'
    )
  })

  it('POST /google/callback -> successfully handle google callback', async () => {
    process.env.CLIENT_URL = 'http://localhost:3000'
    const res = await supertest(app).get('/api/v1/auth/google/callback')

    expect(res.statusCode).toBe(302)
    expect(res.headers.location).toBe('http://localhost:3000')

    expect(signJwt).toHaveBeenCalledTimes(2)
    expect(setCache).toHaveBeenCalled()
    expect(setAccessToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalled()
  })

  it('POST /facebook/callback -> successfully handle facebook callback', async () => {
    process.env.CLIENT_URL = 'http://localhost:3000'
    const res = await supertest(app).get('/api/v1/auth/facebook/callback')

    expect(res.statusCode).toBe(302)
    expect(res.headers.location).toBe('http://localhost:3000')

    expect(signJwt).toHaveBeenCalledTimes(2)
    expect(setCache).toHaveBeenCalled()
    expect(setAccessToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalled()
  })

  it('POST /login -> successfully login admin', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'admin',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(200)
    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Login admin berhasil')

    expect(setAccessToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalledWith('hashed', '00000000')
    expect(signJwt).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        id: 1,
        name: 'dims',
        email: 'sample@gmail.com',
        role: 'admin'
      }),
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )

    expect(signJwt).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        jti: expect.any(String),
        id: 1,
        name: 'dims',
        email: 'sample@gmail.com',
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
  })

  it('POST /login-admin -> failed to login because required fields not provided', async () => {
    const requestBody = {
      email: 'sample@gmail.com'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password harus diisi')

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
  })

  it('POST /login-admin -> failed to login because email not exists in database', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(404)
    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat login: User dengan email sample@gmail.com tidak ditemukan'
    )

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /login-admin -> failed to login if user role is user, because this route only for admin', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin ').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Login ini hanya untuk admin')

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /login-admin -> failed to login because password doenst match', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'dims',
      role: 'admin',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    vi.mocked(verifyPassword).mockResolvedValue(false)
    const requestBody = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin ').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password salah')

    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(verifyPassword).toHaveBeenCalledWith('hashed', '00000000')
  })

  it('POST /logout -> successfully logout', async () => {
    const mockRefreshToken = 'kjhasldkjq3'
    const res = await supertest(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', [`refreshToken=${mockRefreshToken}`])
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Logout berhasil')

    expect(clearAuthCookies).toHaveBeenCalled()
    expect(verifyJwtToken).toHaveBeenCalled()
    expect(redis.del).toHaveBeenCalled()
  })

  it('GET /profile -> successfully get profile', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const res = await supertest(app)
      .get('/api/v1/auth/profile')
      .set('Cookie', ['accessToken=fake-access-token'])
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Profile berhasil diambil')

    expect(res.body.data).toEqual(
      expect.objectContaining({
        id: 1,
        name: 'Test User',
        role: 'user',
        email: 'test@mail.com',
        is_verified: false,
        profile_url: null,
        provider: 'local',
        providerId: null,
        created_at: expect.any(String),
        updated_at: expect.any(String)
      })
    )

    expect(verifyJwtToken).toHaveBeenCalledWith('fake-access-token', 'ACCESS_TOKEN_PUBLIC_KEY')
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('GET /profile -> failed because user not authorized', async () => {
    const res = await supertest(app).get('/api/v1/auth/profile').expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Akses ditolak, silahkan login terlebih dahulu')
  })

  it('GET /profile -> failed because user not exists in database', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)
    const res = await supertest(app)
      .get('/api/v1/auth/profile')
      .set('Cookie', ['accessToken=fake-access-token'])
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat mengambil data profile: User dengan id 1 tidak ditemukan'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('PATCH /update-profile -> successfully update the profile', async () => {
    vi.mocked(checkExists).mockResolvedValue(undefined)

    vi.mocked(prismaMock.user.update).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app)
      .patch('/api/v1/auth/update-profile')
      .set('Cookie', ['accessToken=fake-token'])
      .field('name', 'New Name')
      .attach('profile_url', Buffer.from('fake image content'), {
        filename: 'avatar.png',
        contentType: 'image/png'
      })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Profile berhasil diupdate')

    expect(checkExists).toHaveBeenCalled()
    expect(uploadImageToImageKit).toHaveBeenCalled()
    expect(prismaMock.user.update).toHaveBeenCalled()
  })

  it('PATCH /update-profile -> failed because user not exists in database', async () => {
    vi.mocked(checkExists).mockRejectedValue(
      new NotFoundException('User dengan id 1 tidak ditemukan')
    )

    const res = await supertest(app)
      .patch('/api/v1/auth/update-profile')
      .set('Cookie', ['accessToken=fake-token'])
      .field('name', 'New Name')
      .attach('profile_url', Buffer.from('fake image content'), {
        filename: 'avatar.png',
        contentType: 'image/png'
      })
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat update profile: User dengan id 1 tidak ditemukan')

    expect(checkExists).toHaveBeenCalled()
  })

  it('PATCH /change-password -> successfully change the password', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    vi.mocked(prismaMock.user.update).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: 'new password',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)

    const res = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', ['accessToken=fake-token'])
      .send({
        oldPassword: 'old password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Password berhasil diubah')

    expect(verifyPassword).toHaveBeenCalledWith('hashed', 'old password')
    expect(hashPassword).toHaveBeenCalledWith('new password')
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).toHaveBeenCalled()
  })

  it('PATCH /change-password -> failed because required field not provided', async () => {
    const res = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', ['accessToken=fake-token'])
      .send({
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat ubah password: Password lama harus diisi')
  })

  it('PATCH /change-password -> failed because user not found in database', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)
    const res = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', ['accessToken=fake-token'])
      .send({
        oldPassword: 'old password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat ubah password: User dengan email test@mail.com tidak ditemukan'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('PATCH /change-password -> failed because new password doesnt match with new password confirmation', async () => {
    const res = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', ['accessToken=fake-token'])
      .send({
        oldPassword: 'old password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new passwordddddddddd'
      })
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat ubah password: Password baru dan konfirmasi password baru tidak cocok'
    )
  })

  it('PATCH /change-password -> failed because old password doenst match', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'test@mail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    vi.mocked(verifyPassword).mockResolvedValue(false)

    const res = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', ['accessToken=fake-token'])
      .send({
        oldPassword: 'old password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat ubah password: Password lama salah')

    expect(verifyPassword).toHaveBeenCalledWith('hashed', 'old password')
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /forgot-password -> successfully send forgot password token to email', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const res = await supertest(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: 'sample@gmail.com' })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Token reset password berhasil dikirim')

    expect(generateVerificationToken).toHaveBeenCalled()
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(sendEmail).toHaveBeenCalledWith({
      email: 'sample@gmail.com',
      subject: 'Reset Password Token untuk reset password Anda',
      html: expect.any(String)
    })
    expect(prismaMock.user.update).toHaveBeenCalled()
  })
  it('POST /forgot-password -> failed because email not exists in database', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)
    const res = await supertest(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: 'sample@gmail.com' })
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat kirim forgot password token: User dengan email sample@gmail.com tidak ditemukan'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /reset-password -> successfully reseting the password', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: 'reset-password',
      reset_password_token_expires_at: new Date(Date.now() + 60 * 60 * 1000),
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    vi.mocked(prismaMock.user.update).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: null,
      reset_password_token_expires_at: null,
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const res = await supertest(app)
      .post('/api/v1/auth/reset-password')
      .send({
        email: 'sample@gmail.com',
        passwordResetCode: 'reset-password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Password berhasil direset')

    expect(hashPassword).toHaveBeenCalledWith('new password')
    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).toHaveBeenCalled()
  })

  it('POST /reset-password -> failed because reset password token is wrong', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: 'wrong',
      reset_password_token_expires_at: new Date(Date.now() + 60 * 60 * 1000),
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const res = await supertest(app)
      .post('/api/v1/auth/reset-password')
      .send({
        email: 'sample@gmail.com',
        passwordResetCode: 'reset-password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat reset password: Token reset password salah')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /reset-password -> failed because user doenst not exists in database', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue(null)
    const res = await supertest(app)
      .post('/api/v1/auth/reset-password')
      .send({
        email: 'sample@gmail.com',
        passwordResetCode: 'reset-password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat reset password: User dengan email sample@gmail.com tidak ditemukan'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('POST /reset-password -> failed because reset password token is expired', async () => {
    vi.mocked(prismaMock.user.findUnique).mockResolvedValue({
      id: 1,
      name: 'Test User',
      role: 'user',
      email: 'sample@gmail.com',
      password: 'hashed',
      is_verified: false,
      verification_token: 'token',
      verification_token_expires_at: new Date(),
      reset_password_token: 'reset-password',
      reset_password_token_expires_at: new Date(Date.now() - 60 * 60 * 1000),
      profile_url: null,
      provider: 'local',
      providerId: null,
      created_at: new Date(),
      updated_at: new Date()
    } as any)
    const res = await supertest(app)
      .post('/api/v1/auth/reset-password')
      .send({
        email: 'sample@gmail.com',
        passwordResetCode: 'reset-password',
        newPassword: 'new password',
        newPasswordConfirmation: 'new password'
      })
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat reset password: Token reset password sudah kadaluarsa'
    )

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
  })

  it('GET /check-auth -> successfully check auth user status because user is authenticated', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/check-auth')
      .set('Cookie', ['accessToken=mock-accesstoken'])
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Autentikasi berhasil')
  })

  it('GET /check-auth -> failed check auth user status because user is not authenticated', async () => {
    const res = await supertest(app).get('/api/v1/auth/check-auth').expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Tidak terautentikasi')
  })
})
