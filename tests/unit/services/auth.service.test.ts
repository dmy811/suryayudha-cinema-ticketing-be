import { beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest'

vi.mock('../../../src/shared/logger/logger')
vi.mock('../../../src/shared/error-handling/middleware/custom-handle')
vi.mock('../../../src/shared/middlewares/validation.middleware', () => ({
  ZodValidation: {
    validate: vi.fn()
  }
}))

import { AuthService } from '../../../src/applications/modules/Auth/auth.service'
import { AuthRepositoryPrisma } from '../../../src/infrastructure/repositories/AuthRepositoryPrisma'
import { logger } from '../../../src/shared/logger/logger'
import { CustomHandleError } from '../../../src/shared/error-handling/middleware/custom-handle'
import { HttpException } from '../../../src/shared/error-handling/exceptions/http.exception'
import { createMockService } from '../../__mocks__/baseMockService'
import { ZodValidation } from '../../../src/shared/middlewares/validation.middleware'
import { BadRequestException } from '../../../src/shared/error-handling/exceptions/bad-request.exception'
import { NotFoundException } from '../../../src/shared/error-handling/exceptions/not-found.exception'
import { UnauthorizedException } from '../../../src/shared/error-handling/exceptions/unauthorized.exception'
import { userFactory } from '../../factories/user'

describe('Auth Service (unit)', () => {
  let authService: AuthService
  let authRepositoryPrismaMock: Partial<AuthRepositoryPrisma>

  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(CustomHandleError).mockReturnValue(new HttpException(500, 'error'))
    vi.mocked(ZodValidation.validate).mockReturnValue({} as any)
    vi.mocked(logger.info).mockReturnValue(logger)
    vi.mocked(logger.error).mockReturnValue(logger)
    vi.mocked(logger.warn).mockReturnValue(logger)

    authRepositoryPrismaMock = createMockService<AuthRepositoryPrisma>([
      'register',
      'resendVerificationLink',
      'verifyEmail',
      'login',
      'loginAdmin',
      'refreshToken',
      'getProfile',
      'updateProfile',
      'changePassword',
      'sendTokenResetPassword',
      'resetPassword'
    ])

    authService = new AuthService(authRepositoryPrismaMock as AuthRepositoryPrisma)
  })

  it('register -> should call repository.register and return user', async () => {
    const registerMock = vi.spyOn(authRepositoryPrismaMock, 'register')
    const returnUser = userFactory()
    registerMock.mockResolvedValue(returnUser)

    const user = await authService['register']({} as any)

    expect(authRepositoryPrismaMock.register).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.register).toHaveBeenCalledWith({} as any)
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(user).toEqual(returnUser)
  })

  it('resendVerificationLink -> should call repository.resendVerificationLink', async () => {
    const resendVerificationLinkMock = vi.spyOn(authRepositoryPrismaMock, 'resendVerificationLink')
    resendVerificationLinkMock.mockResolvedValue(undefined)

    await authService['resendVerificationLink']('example@gmail.com')

    expect(authRepositoryPrismaMock.resendVerificationLink).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.resendVerificationLink).toHaveBeenCalledWith(
      'example@gmail.com'
    )
  })
  it('resendVerificationLink -> should return and custom handle error', async () => {
    const resendVerificationLinkMock = vi.spyOn(authRepositoryPrismaMock, 'resendVerificationLink')
    resendVerificationLinkMock.mockRejectedValue(new NotFoundException('err'))

    try {
      await authService['resendVerificationLink']('example@gmail.com')
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }

    expect(authRepositoryPrismaMock.resendVerificationLink).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.resendVerificationLink).toHaveBeenCalledWith(
      'example@gmail.com'
    )
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('verify email -> should call repository.verifyEmail', async () => {
    const verifyEmailMock = vi.spyOn(authRepositoryPrismaMock, 'verifyEmail')
    verifyEmailMock.mockResolvedValue()

    await authService['verifyEmail']('token', 'sample@gmail.com')
    expect(authRepositoryPrismaMock.verifyEmail).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.verifyEmail).toHaveBeenCalledWith('token', 'sample@gmail.com')
  })

  it('verify email -> should call repository.verifyEmail and custom handle error', async () => {
    const verifyEmailMock = vi.spyOn(authRepositoryPrismaMock, 'verifyEmail')
    verifyEmailMock.mockRejectedValue(new BadRequestException('token wrong'))
    try {
      await authService['verifyEmail']('token', 'sample@gmail.com')
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }
    expect(authRepositoryPrismaMock.verifyEmail).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.verifyEmail).toHaveBeenCalledWith('token', 'sample@gmail.com')
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('login -> login for user should call repository.login and return accessToken and refreshToken', async () => {
    const loginMock = vi.spyOn(authRepositoryPrismaMock, 'login')
    loginMock.mockResolvedValue({ accessToken: 'access token', refreshToken: 'refresh token' })
    const loginPayload = {
      email: 'sample@gmail.com',
      password: '00000000'
    }

    const result = await authService['login']('user', loginPayload)

    expect(authRepositoryPrismaMock.login).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.login).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toStrictEqual({ accessToken: 'access token', refreshToken: 'refresh token' })
  })

  it('login -> login for admin should call repository.login and return accessToken and refreshToken', async () => {
    const loginMock = vi.spyOn(authRepositoryPrismaMock, 'loginAdmin')
    loginMock.mockResolvedValue({ accessToken: 'access token', refreshToken: 'refresh token' })
    const loginPayload = {
      email: 'admin@gmail.com',
      password: '00000000'
    }

    const result = await authService['login']('admin', loginPayload)

    expect(authRepositoryPrismaMock.loginAdmin).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.loginAdmin).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toStrictEqual({ accessToken: 'access token', refreshToken: 'refresh token' })
  })

  it('login -> should call repository.login and custom handle error', async () => {
    const loginMock = vi.spyOn(authRepositoryPrismaMock, 'login')
    loginMock.mockRejectedValue(new BadRequestException('badd badd'))
    const loginPayload = {
      email: 'sample@gmail.com'
    }

    try {
      await authService['login']('user', loginPayload)
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }

    expect(authRepositoryPrismaMock.login).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.login).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('refresh token -> should call repository.refreshToken and return newAccessToken and newRefreshTokenr', async () => {
    const refreshTokenMock = vi.spyOn(authRepositoryPrismaMock, 'refreshToken')
    refreshTokenMock.mockResolvedValue({
      newAccessToken: 'new access token',
      newRefreshToken: 'new refresh token'
    })
    const rt = 'refreshtoken'
    const result = await authService['refreshToken'](rt)

    expect(authRepositoryPrismaMock.refreshToken).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.refreshToken).toHaveBeenCalledWith(rt)
    expect(result).toStrictEqual({
      newAccessToken: 'new access token',
      newRefreshToken: 'new refresh token'
    })
  })

  it('refresh token -> should call repository.refreshToken and custom handle error', async () => {
    const refreshTokenMock = vi.spyOn(authRepositoryPrismaMock, 'refreshToken')
    refreshTokenMock.mockRejectedValue(new UnauthorizedException('unauthorized'))
    const rt = 'refreshtoken'
    try {
      await authService['refreshToken'](rt)
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }

    expect(authRepositoryPrismaMock.refreshToken).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.refreshToken).toHaveBeenCalledWith(rt)
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('get profile -> should call repository.getProfile and return a user', async () => {
    const getProfileMock = vi.spyOn(authRepositoryPrismaMock, 'getProfile')
    const returnUser = userFactory()
    getProfileMock.mockResolvedValue(returnUser)

    const result = await authService['getProfile'](1)
    expect(authRepositoryPrismaMock.getProfile).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.getProfile).toHaveBeenCalledWith(1)
    expect(result).toBe(returnUser)
  })

  it('get profile -> should call repository.getProfile and custorm handle error', async () => {
    const getProfileMock = vi.spyOn(authRepositoryPrismaMock, 'getProfile')
    getProfileMock.mockRejectedValue(new NotFoundException('not found'))

    try {
      await authService['getProfile'](1)
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }
    expect(authRepositoryPrismaMock.getProfile).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.getProfile).toHaveBeenCalledWith(1)
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('update profile -> should call repository.updateProfile and return a user', async () => {
    const updateProfileMock = vi.spyOn(authRepositoryPrismaMock, 'updateProfile')
    const returnUser = userFactory()
    updateProfileMock.mockResolvedValue(returnUser)

    const result = await authService['updateProfile'](1, { name: 'update' })
    expect(authRepositoryPrismaMock.updateProfile).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.updateProfile).toHaveBeenCalledWith(1, {})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toBe(returnUser)
  })

  it('update profile -> should call repository.updateProfile and custom handle error', async () => {
    const updateProfileMock = vi.spyOn(authRepositoryPrismaMock, 'updateProfile')
    updateProfileMock.mockRejectedValue(new BadRequestException('bad bad'))

    try {
      await authService['updateProfile'](1, { name: 'update' })
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }
    expect(authRepositoryPrismaMock.updateProfile).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.updateProfile).toHaveBeenCalledWith(1, {})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('change password -> should call repository.changePassword and return a user', async () => {
    const changePasswordMock = vi.spyOn(authRepositoryPrismaMock, 'changePassword')
    const returnUser = userFactory()
    changePasswordMock.mockResolvedValue(returnUser)

    const result = await authService['changePassword']('sample@gmail.com', {})
    expect(authRepositoryPrismaMock.changePassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.changePassword).toHaveBeenCalledWith('sample@gmail.com', {})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toBe(returnUser)
  })

  it('change password -> should call repository.changePassword and custom handle error', async () => {
    const changePasswordMock = vi.spyOn(authRepositoryPrismaMock, 'changePassword')
    changePasswordMock.mockRejectedValue(new BadRequestException('bad bad'))

    try {
      await authService['changePassword']('sample@gmail.com', {})
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }
    expect(authRepositoryPrismaMock.changePassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.changePassword).toHaveBeenCalledWith('sample@gmail.com', {})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('send token reset password -> should call repository.sendTokenResetPassword', async () => {
    const sendTokenResetPassword = vi.spyOn(authRepositoryPrismaMock, 'sendTokenResetPassword')
    sendTokenResetPassword.mockResolvedValue()

    await authService['sendTokenResetPassword']({ email: 'sample@gmail.com' })
    expect(authRepositoryPrismaMock.sendTokenResetPassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.sendTokenResetPassword).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
  })

  it('send token reset password -> should call repository.sendTokenResetPassword and custom handle error', async () => {
    const sendTokenResetPassword = vi.spyOn(authRepositoryPrismaMock, 'sendTokenResetPassword')
    sendTokenResetPassword.mockRejectedValue(new BadRequestException('bad bad'))

    try {
      await authService['sendTokenResetPassword']({ email: 'sample@gmail.com' })
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }
    expect(authRepositoryPrismaMock.sendTokenResetPassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.sendTokenResetPassword).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(CustomHandleError).toHaveBeenCalled()
  })

  it('reset password -> should call repository.resetPassword and return a user', async () => {
    const resetPasswordMock = vi.spyOn(authRepositoryPrismaMock, 'resetPassword')
    const returnUser = userFactory()
    resetPasswordMock.mockResolvedValue(returnUser)

    const result = await authService['resetPassword']({})
    expect(authRepositoryPrismaMock.resetPassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.resetPassword).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toBe(returnUser)
  })

  it('reset password -> should call repository.resetPassword and custom handle error', async () => {
    const resetPasswordMock = vi.spyOn(authRepositoryPrismaMock, 'resetPassword')
    resetPasswordMock.mockRejectedValue(new BadRequestException('bad bad'))

    try {
      await authService['resetPassword']({})
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }
    expect(authRepositoryPrismaMock.resetPassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.resetPassword).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(CustomHandleError).toHaveBeenCalled()
  })
})
