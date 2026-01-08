import '../../__mocks__/mockRedis'
import { beforeEach, describe, it, vi, Mock, expect } from 'vitest'

// cara di bawah ini akan error mock kehilangan return value karena di beforeEach saya clearAllMocks
// vi.mock('../../../src/shared/helpers/generateVerificationToken', () => ({
//   generateVerificationToken: vi.fn().mockReturnValue('verif-token')
// }))

// vi.mock('../../../src/shared/helpers/setCookies', () => ({
//   setAccessToken: vi.fn()
// }))

// vi.mock('../../../src/infrastructure/config/jwt', () => ({
//   signJwt: vi.fn().mockReturnValue('token')
// }))

// vi.mock('../../../src/shared/logger/logger', () => ({
//   logger: {
//     info: vi.fn(),
//     error: vi.fn(),
//     warn: vi.fn()
//   }
// }))

vi.mock('../../../src/shared/helpers/generateVerificationToken')
vi.mock('../../../src/shared/helpers/setCookies')
vi.mock('../../../src/infrastructure/config/jwt')
vi.mock('../../../src/shared/logger/logger')
vi.mock('../../../src/infrastructure/cache/setCache')
vi.mock('../../../src/shared/helpers/clearCookies')

// mock base
import { createMockService } from '../../__mocks__/baseMockService'
import { mockReq, mockRes, mockNext } from '../../__mocks__/mockReqRes'

import { AuthController } from '../../../src/applications/modules/Auth/auth.controller'
import { AuthService } from '../../../src/applications/modules/Auth/auth.service'
import { generateVerificationToken } from '../../../src/shared/helpers/generateVerificationToken'
import { signJwt, verifyJwtToken } from '../../../src/infrastructure/config/jwt'
import { logger } from '../../../src/shared/logger/logger'
import { BadRequestException } from '../../../src/shared/error-handling/exceptions/bad-request.exception'
import { UnauthorizedException } from '../../../src/shared/error-handling/exceptions/unauthorized.exception'
import { userFactory } from '../../factories/user'
import { setAccessToken, setRefreshToken } from '../../../src/shared/helpers/setCookies'
import { setCache } from '../../../src/infrastructure/cache/setCache'
import { clearAuthCookies } from '../../../src/shared/helpers/clearCookies'
import redis from '../../../src/infrastructure/config/redis'

describe('AuthController (unit)', () => {
  let authController: AuthController
  let authServiceMock: Partial<AuthService>

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(generateVerificationToken).mockReturnValue('verif-token')
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
    vi.mocked(setCache).mockResolvedValue(undefined)
    vi.mocked(logger.info).mockReturnValue(logger)
    vi.mocked(logger.error).mockReturnValue(logger)
    vi.mocked(logger.warn).mockReturnValue(logger)

    authServiceMock = createMockService<AuthService>([
      'register',
      'resendVerificationLink',
      'verifyEmail',
      'login',
      'getProfile',
      'updateProfile',
      'changePassword',
      'sendTokenResetPassword',
      'resetPassword'
    ])
    authController = new AuthController(authServiceMock as AuthService)
  })

  it('register -> should call service.register and return 201', async () => {
    const req = mockReq({
      body: { email: 'example@gmail.com', name: 'example', password: '12345678' }
    })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.register!).mockResolvedValue(
      userFactory({ id: 1, email: 'example@gmail.com' })
    )

    await authController['register'](req as any, res as any, next)

    expect(authServiceMock.register).toHaveBeenCalled()
    expect(authServiceMock.register).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'example@gmail.com',
        name: 'example',
        password: '12345678',
        role: 'user',
        is_verified: false,
        verification_token: 'verif-token',
        verification_token_expires_at: expect.any(Date),
        profile_url: 'https://ik.imagekit.io/yxctvbjvh/profilepic.png?updatedAt=1734338115538'
      })
    )
    expect(generateVerificationToken).toHaveBeenCalled()
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ from: 'auth:register:controller', message: expect.any(String) })
    )
    expect(res.status).toHaveBeenCalledWith(201)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        message:
          'Berhasil register dan verifikasi link telah dikirim ke email anda!, silahkan cek email untuk verifikasi'
      })
    )
  })

  it('register -> service throws an error and should call next with error ', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com' } })
    const res = mockRes()
    const next = mockNext()
    const err = new Error('zod error because user only send email')
    vi.mocked(authServiceMock.register!).mockRejectedValue(err)
    await authController['register'](req as any, res as any, next)

    expect(authServiceMock.register).toHaveBeenCalled()
    expect(next).toHaveBeenCalledWith(err)
    expect(res.status).not.toHaveBeenCalled()
    expect(res.json).not.toHaveBeenCalled()
  })

  it('resendVerificationLink -> should call service.resendVerificationLink and return 200', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com' } })
    const res = mockRes()
    const next = mockNext()
    vi.mocked(authServiceMock.resendVerificationLink!).mockResolvedValue(undefined)

    await authController['resendVerificationLink'](req as any, res as any, next)

    expect(authServiceMock.resendVerificationLink).toHaveBeenCalled()
    expect(authServiceMock.resendVerificationLink).toHaveBeenCalledWith('example@gmail.com')
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        message: 'Link verifikasi berhasil dikirim ulang'
      })
    )
  })

  it('verifyEmail -> should call service.verifyEmail and return 200', async () => {
    const req = mockReq({ query: { token: 'token', email: 'example@gmail.com' } })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.verifyEmail!).mockResolvedValue(undefined)

    await authController['verifyEmail'](req as any, res as any, next)

    expect(authServiceMock.verifyEmail).toHaveBeenCalled()
    expect(authServiceMock.verifyEmail).toHaveBeenCalledWith('token', 'example@gmail.com')
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        message: 'Email berhasil diverifikasi'
      })
    )
  })

  it('verifyEmail -> should return bad request error', async () => {
    const req = mockReq()
    const res = mockRes()
    const next = mockNext()

    await authController['verifyEmail'](req as any, res as any, next)

    const error = next.mock.calls[0][0]
    expect(authServiceMock.verifyEmail).not.toHaveBeenCalled()
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(BadRequestException)
    expect(error.message).toBe('Token dan email diperlukan untuk verifikasi')
    expect(res.status).not.toHaveBeenCalled()
    expect(res.json).not.toHaveBeenCalled()
  })

  it('login -> should call service.login, setAccessToken and return 200', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com', password: '12345678' } })
    const res = mockRes()
    const next = mockNext()

    const accessToken: string = 'access token'
    const refreshToken: string = 'refresh token'
    vi.mocked(authServiceMock.login!).mockResolvedValue({ accessToken, refreshToken })

    await authController['login'](req as any, res as any, next)

    expect(authServiceMock.login).toHaveBeenCalled()
    expect(authServiceMock.login).toHaveBeenCalledWith('user', {
      email: 'example@gmail.com',
      password: '12345678'
    })
    expect(setAccessToken).toHaveBeenCalled()
    expect(setAccessToken).toHaveBeenCalledWith(accessToken, res)
    expect(setRefreshToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalledWith(refreshToken, res)
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        message: 'Login berhasil'
      })
    )
  })

  it('login -> should call next with Bad Request error instance', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com' } })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.login!).mockRejectedValue(
      new BadRequestException('password not provided')
    )

    await authController['login'](req as any, res as any, next)

    const err = next.mock.calls[0][0]
    expect(authServiceMock.login).toHaveBeenCalled()
    expect(next).toHaveBeenCalled()
    expect(err).toBeInstanceOf(BadRequestException)
    expect(err.message).toBe('password not provided')
    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
    expect(res.json).not.toHaveBeenCalled()
  })

  it('googleOauthCallback -> should call next and return an UnauthoriedError', async () => {
    const req = mockReq()
    const res = mockRes()
    const next = mockNext()

    await authController['googleOauthCallback'](req as any, res as any, next)
    const error = next.mock.calls[0][0]
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(UnauthorizedException)
    expect(error.message).toBe('User tidak ditemukan dari google oauth')
    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
    expect(signJwt).not.toBeCalled()
    expect(res.redirect).not.toBeCalled()
  })

  it('googleOauthCallback -> should successful got the callback and req.user also create a token', async () => {
    const req = mockReq({ user: { id: 8, name: 'name', email: 'name@gmail.com', role: 'user' } })
    const res = mockRes()
    const next = mockNext()

    await authController['googleOauthCallback'](req as any, res as any, next)

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
    expect(setAccessToken).toHaveBeenCalled()
    expect(setAccessToken).toHaveBeenCalledWith('token', res)
    expect(setRefreshToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalledWith('token', res)
    expect(setCache).toHaveBeenCalled()
    expect(setCache).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.any(Number)
    )
    expect(res.redirect).toHaveBeenCalled()
  })

  it('facebookOauthCallback -> should call next and return an UnauthoriedError', async () => {
    const req = mockReq()
    const res = mockRes()
    const next = mockNext()

    await authController['facebookOauthCallback'](req as any, res as any, next)
    const error = next.mock.calls[0][0]
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(UnauthorizedException)
    expect(error.message).toBe('User tidak ditemukan dari facebook oauth')
    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(setCache).not.toHaveBeenCalled()
    expect(signJwt).not.toBeCalled()
    expect(res.redirect).not.toBeCalled()
  })

  it('facebookOauthCallback -> should successful got the callback and req.user also create a token', async () => {
    const req = mockReq({ user: { id: 8, name: 'name', email: 'name@gmail.com', role: 'user' } })
    const res = mockRes()
    const next = mockNext()

    await authController['facebookOauthCallback'](req as any, res as any, next)

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
    expect(setAccessToken).toHaveBeenCalled()
    expect(setAccessToken).toHaveBeenCalledWith('token', res)
    expect(setRefreshToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalledWith('token', res)
    expect(setCache).toHaveBeenCalled()
    expect(setCache).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.any(Number)
    )
    expect(res.redirect).toHaveBeenCalled()
  })

  it('login admin -> should call service.login, setAccessToken and return 200', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com', password: '12345678' } })
    const res = mockRes()
    const next = mockNext()

    const accessToken: string = 'access token'
    const refreshToken: string = 'refresh token'
    vi.mocked(authServiceMock.login!).mockResolvedValue({ accessToken, refreshToken })

    await authController['loginAdmin'](req as any, res as any, next)

    expect(authServiceMock.login).toHaveBeenCalled()
    expect(authServiceMock.login).toHaveBeenCalledWith('admin', {
      email: 'example@gmail.com',
      password: '12345678'
    })
    expect(setAccessToken).toHaveBeenCalled()
    expect(setAccessToken).toHaveBeenCalledWith(accessToken, res)
    expect(setRefreshToken).toHaveBeenCalled()
    expect(setRefreshToken).toHaveBeenCalledWith(refreshToken, res)
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        message: 'Login admin berhasil'
      })
    )
  })

  it('login admin -> should call next with Bad Request error instance', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com' } })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.login!).mockRejectedValue(
      new BadRequestException('password not provided')
    )

    await authController['loginAdmin'](req as any, res as any, next)

    const err = next.mock.calls[0][0]
    expect(authServiceMock.login).toHaveBeenCalled()
    expect(next).toHaveBeenCalled()
    expect(err).toBeInstanceOf(BadRequestException)
    expect(err.message).toBe('password not provided')
    expect(setAccessToken).not.toHaveBeenCalled()
    expect(setRefreshToken).not.toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
    expect(res.json).not.toHaveBeenCalled()
  })

  it('logout -> should call res.clearCookie and return 200', async () => {
    const req = mockReq({ cookies: { refreshToken: 'refresh token' } })
    const res = mockRes()
    const next = mockNext()

    await authController['logout'](req as any, res as any, next)

    expect(redis.del).toHaveBeenCalled()
    expect(redis.del).toHaveBeenCalledTimes(1)
    expect(clearAuthCookies).toHaveBeenCalled()
    expect(clearAuthCookies).toHaveBeenCalledWith(res)
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        message: 'Logout berhasil'
      })
    )
  })

  it('getProfile -> should call service.getProfile and return 200', async () => {
    const req = mockReq({
      user: { id: 8, name: 'name', email: 'name@gmail.com', role: 'user' }
    })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.getProfile!).mockResolvedValue(
      userFactory({ id: 8, name: 'name', email: 'name@gmail.com', role: 'user' })
    )

    await authController['getProfile'](req as any, res as any, next)

    expect(authServiceMock.getProfile).toHaveBeenCalled()
    expect(authServiceMock.getProfile).toHaveBeenCalledWith(8)
    expect(res.status).toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(200)
  })

  it('updateProfile -> should call service.updateProfile and return 200', async () => {
    const req = mockReq({
      user: { id: 8, name: 'name', email: 'name@gmail.com', role: 'user' },
      body: { name: 'name', email: 'name@gmail.com' }
    })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.updateProfile!).mockResolvedValue(
      userFactory({ id: 8, name: 'name', email: 'name@gmail.com', role: 'user' })
    )

    await authController['updateProfile'](req as any, res as any, next)

    expect(authServiceMock.updateProfile).toHaveBeenCalled()
    expect(authServiceMock.updateProfile).toHaveBeenCalledWith(8, {
      name: 'name',
      email: 'name@gmail.com'
    })
    expect(res.status).toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(200)
  })

  it('change password -> should call service.changePassword and return 200', async () => {
    const req = mockReq({
      user: { id: 8, name: 'name', email: 'name@gmail.com', role: 'user' },
      body: {
        oldPassword: '11111111',
        newPassword: '0000000000',
        newPasswordConfirmation: '0000000000'
      }
    })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.changePassword!).mockResolvedValue(
      userFactory({
        id: 8,
        name: 'name',
        email: 'name@gmail.com',
        role: 'user',
        password: '0000000000'
      })
    )

    await authController['changePassword'](req as any, res as any, next)

    expect(authServiceMock.changePassword).toHaveBeenCalled()
    expect(res.status).toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(200)
  })

  it('change password -> should call next and return an error instance of bad request', async () => {
    const req = mockReq({
      user: { id: 8, name: 'name', email: 'name@gmail.com', role: 'user' },
      body: {
        oldPassword: '11111111',
        newPassword: '9999999999999',
        newPasswordConfirmation: '0000000000'
      }
    })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.changePassword!).mockRejectedValue(
      new BadRequestException("new password doesn't match with new password confirmation")
    )

    await authController['changePassword'](req as any, res as any, next)

    const error = next.mock.calls[0][0]
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(BadRequestException)
    expect(error.message).toBe("new password doesn't match with new password confirmation")
    expect(authServiceMock.changePassword).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('sendTokenResetPassword -> should call service.sendTokenResetPassword and return 200', async () => {
    const req = mockReq({ body: { email: 'example@gmail.com' } })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.sendTokenResetPassword!).mockResolvedValue(undefined)

    await authController['sendTokenResetPassword'](req as any, res as any, next)

    expect(authServiceMock.sendTokenResetPassword).toHaveBeenCalled()
    expect(authServiceMock.sendTokenResetPassword).toHaveBeenCalledWith({
      email: 'example@gmail.com'
    })
    expect(res.status).toHaveBeenCalledWith(200)
  })

  it('sendTokenResetPassword -> should call next and return an error instance of bad request', async () => {
    const req = mockReq()
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.sendTokenResetPassword!).mockRejectedValue(
      new BadRequestException('email not provided')
    )

    await authController['sendTokenResetPassword'](req as any, res as any, next)

    const error = next.mock.calls[0][0]
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(BadRequestException)
    expect(error.message).toBe('email not provided')
    expect(authServiceMock.sendTokenResetPassword).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('resetPassword -> should call service.resetPassword and return 200', async () => {
    const req = mockReq({
      body: {
        email: 'example@gmail.com',
        passwordResetCode: '123456',
        newPassword: '12345600',
        newPasswordConfirmation: '12345600'
      }
    })
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.resetPassword!).mockResolvedValue(
      userFactory({ email: 'example@gmail.com', password: '12345600' })
    )

    await authController['resetPassword'](req as any, res as any, next)

    expect(authServiceMock.resetPassword).toHaveBeenCalled()
    expect(authServiceMock.resetPassword).toHaveBeenCalledWith({
      email: 'example@gmail.com',
      passwordResetCode: '123456',
      newPassword: '12345600',
      newPasswordConfirmation: '12345600'
    })
    expect(res.status).toHaveBeenCalledWith(200)
  })

  it('resetPassword -> should call next and return an error instance of bad request', async () => {
    const req = mockReq()
    const res = mockRes()
    const next = mockNext()

    vi.mocked(authServiceMock.resetPassword!).mockRejectedValue(
      new BadRequestException('email not provided')
    )

    await authController['resetPassword'](req as any, res as any, next)

    const error = next.mock.calls[0][0]
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(BadRequestException)
    expect(error.message).toBe('email not provided')
    expect(authServiceMock.resetPassword).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('checkAuthentication -> should call service.checkAuthentication and return 200', async () => {
    const req = mockReq({ cookies: { accessToken: 'token' } })
    const res = mockRes()
    const next = mockNext()

    await authController['checkAuthentication'](req as any, res as any, next)
    expect(res.status).toHaveBeenCalled()
    expect(res.status).toHaveBeenCalledWith(200)
    expect(res.json).toHaveBeenCalledWith({ success: true, message: 'Autentikasi berhasil' })
  })

  it('checkAuthentication -> should call next and return an error instance of unauthorized', async () => {
    const req = mockReq()
    const res = mockRes()
    const next = mockNext()

    await authController['checkAuthentication'](req as any, res as any, next)
    const error = next.mock.calls[0][0]
    expect(next).toHaveBeenCalled()
    expect(error).toBeInstanceOf(UnauthorizedException)
    expect(error.message).toBe('Tidak terautentikasi')
    expect(res.status).not.toHaveBeenCalled()
    expect(res.json).not.toHaveBeenCalled()
  })
})
