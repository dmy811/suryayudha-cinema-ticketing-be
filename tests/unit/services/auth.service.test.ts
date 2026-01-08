import { beforeEach, describe, expect, it, vi } from 'vitest'

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
import { ZodError } from 'zod'

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
    const returnUser = userFactory()
    vi.mocked(authRepositoryPrismaMock.register!).mockResolvedValue(returnUser)

    const user = await authService['register']({} as any)

    expect(authRepositoryPrismaMock.register).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.register).toHaveBeenCalledWith({} as any)
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(user).toEqual(returnUser)
  })

  it('register -> should call repository.register and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.register!).mockRejectedValue(
      new BadRequestException('user already exists')
    )

    try {
      await authService['register']({} as any)
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }

    expect(authRepositoryPrismaMock.register).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.register).toHaveBeenCalledWith({} as any)
    expect(ZodValidation.validate).toHaveBeenCalled()
  })

  it('register -> should throw and validation zod error', async () => {
    vi.mocked(ZodValidation.validate).mockImplementation(() => {
      throw new ZodError([])
    })

    try {
      await authService['register']({} as any)
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException)
    }

    expect(authRepositoryPrismaMock.register).not.toHaveBeenCalled()
    expect(authRepositoryPrismaMock.register).not.toHaveBeenCalledWith({} as any)
    expect(ZodValidation.validate).toHaveBeenCalled()
  })

  it('resendVerificationLink -> should call repository.resendVerificationLink', async () => {
    vi.mocked(authRepositoryPrismaMock.resendVerificationLink!).mockResolvedValue(undefined)

    await authService['resendVerificationLink']('example@gmail.com')

    expect(authRepositoryPrismaMock.resendVerificationLink).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.resendVerificationLink).toHaveBeenCalledWith(
      'example@gmail.com'
    )
  })
  it('resendVerificationLink -> should return and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.resendVerificationLink!).mockRejectedValue(
      new NotFoundException('err')
    )

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
    vi.mocked(authRepositoryPrismaMock.verifyEmail!).mockResolvedValue()

    await authService['verifyEmail']('token', 'sample@gmail.com')
    expect(authRepositoryPrismaMock.verifyEmail).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.verifyEmail).toHaveBeenCalledWith('token', 'sample@gmail.com')
  })

  it('verify email -> should call repository.verifyEmail and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.verifyEmail!).mockRejectedValue(
      new BadRequestException('token wrong')
    )
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
    vi.mocked(authRepositoryPrismaMock.login!).mockResolvedValue({
      accessToken: 'access token',
      refreshToken: 'refresh token'
    })
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
    vi.mocked(authRepositoryPrismaMock.loginAdmin!).mockResolvedValue({
      accessToken: 'access token',
      refreshToken: 'refresh token'
    })
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
    vi.mocked(authRepositoryPrismaMock.login!).mockRejectedValue(
      new BadRequestException('badd badd')
    )
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
    vi.mocked(authRepositoryPrismaMock.refreshToken!).mockResolvedValue({
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
    vi.mocked(authRepositoryPrismaMock.refreshToken!).mockRejectedValue(
      new UnauthorizedException('unauthorized')
    )

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
    const returnUser = userFactory()
    vi.mocked(authRepositoryPrismaMock.getProfile!).mockResolvedValue(returnUser)

    const result = await authService['getProfile'](1)
    expect(authRepositoryPrismaMock.getProfile).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.getProfile).toHaveBeenCalledWith(1)
    expect(result).toBe(returnUser)
  })

  it('get profile -> should call repository.getProfile and custorm handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.getProfile!).mockRejectedValue(
      new NotFoundException('not found')
    )

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
    const returnUser = userFactory()
    vi.mocked(authRepositoryPrismaMock.updateProfile!).mockResolvedValue(returnUser)

    const result = await authService['updateProfile'](1, { name: 'update' })
    expect(authRepositoryPrismaMock.updateProfile).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.updateProfile).toHaveBeenCalledWith(1, {})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toBe(returnUser)
  })

  it('update profile -> should call repository.updateProfile and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.updateProfile!).mockRejectedValue(
      new BadRequestException('bad bad')
    )

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
    const returnUser = userFactory()
    vi.mocked(authRepositoryPrismaMock.changePassword!).mockResolvedValue(returnUser)

    const result = await authService['changePassword']('sample@gmail.com', {})
    expect(authRepositoryPrismaMock.changePassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.changePassword).toHaveBeenCalledWith('sample@gmail.com', {})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toBe(returnUser)
  })

  it('change password -> should call repository.changePassword and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.changePassword!).mockRejectedValue(
      new BadRequestException('bad bad')
    )

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
    vi.mocked(authRepositoryPrismaMock.sendTokenResetPassword!).mockResolvedValue()

    await authService['sendTokenResetPassword']({ email: 'sample@gmail.com' })
    expect(authRepositoryPrismaMock.sendTokenResetPassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.sendTokenResetPassword).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
  })

  it('send token reset password -> should call repository.sendTokenResetPassword and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.sendTokenResetPassword!).mockRejectedValue(
      new BadRequestException('bad bad')
    )

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
    const returnUser = userFactory()
    vi.mocked(authRepositoryPrismaMock.resetPassword!).mockResolvedValue(returnUser)

    const result = await authService['resetPassword']({})
    expect(authRepositoryPrismaMock.resetPassword).toHaveBeenCalled()
    expect(authRepositoryPrismaMock.resetPassword).toHaveBeenCalledWith({})
    expect(ZodValidation.validate).toHaveBeenCalled()
    expect(result).toBe(returnUser)
  })

  it('reset password -> should call repository.resetPassword and custom handle error', async () => {
    vi.mocked(authRepositoryPrismaMock.resetPassword!).mockRejectedValue(
      new BadRequestException('bad bad')
    )

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
