import '../__mocks__/mockRedis'
import { describe, expect, it, beforeEach, vi } from 'vitest'

vi.mock('../../src/shared/helpers/generateVerificationToken')
vi.mock('../../src/shared/helpers/setCookies')
vi.mock('../../src/infrastructure/config/jwt')
vi.mock('../../src/shared/logger/logger')
vi.mock('../../src/shared/helpers/clearCookies')
vi.mock('../../src/infrastructure/config/imagekit.config', () => ({
  uploadImageToImageKit: vi.fn()
}))
vi.mock('../../src/infrastructure/config/nodemailer')
vi.mock('../../src/shared/helpers/passwordEncrypt')
vi.mock('../../src/infrastructure/cache/setCache')

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
      name: 'example',
      email: 'example@gmail.com',
      role: 'user',
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

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody)
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

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody)
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

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody)
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

    const res = await supertest(app).post('/api/v1/auth/register').send(requestBody)
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

    const res = await supertest(app).get(
      '/api/v1/auth/verify-email?token=978241&email=sample@gmail.com'
    )

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

    const res = await supertest(app).get(
      '/api/v1/auth/verify-email?token=978241&email=sample@gmail.com'
    )

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

    const res = await supertest(app).get(
      '/api/v1/auth/verify-email?token=978241&email=sample@gmail.com'
    )

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

    const res = await supertest(app).get(
      '/api/v1/auth/verify-email?token=978241&email=sample@gmail.com'
    )

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Token verifikasi sudah kadaluarsa')

    expect(prismaMock.user.findUnique).toHaveBeenCalled()
    expect(prismaMock.user.update).not.toHaveBeenCalled()
  })

  // login
})
