import { User } from '@prisma/client'
import { CustomHandleError } from '@shared/error-handling/middleware/custom-handle'
import {
  ChangePasswordPayload,
  LoginPayload,
  RegisterPayload,
  ResetPasswordPayload
} from '@infrastructure/types/entities/AuthTypes'

import { UserUpdatePayload } from '@infrastructure/types/entities/UserTypes'
import { AuthValidation } from './auth.validation'
import { ZodValidation } from '@shared/middlewares/validation.middleware'
import { AuthRepositoryPrisma } from '@infrastructure/repositories/AuthRepositoryPrisma'

export class AuthService {
  constructor(private readonly repository: AuthRepositoryPrisma) {}

  async register(data: RegisterPayload): Promise<User> {
    try {
      const userPayloadRequest = ZodValidation.validate(AuthValidation.REGISTER, data)
      return await this.repository.register(userPayloadRequest)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat membuat user'
      })
    }
  }

  async resendVerificationLink(email: string): Promise<void> {
    try {
      await this.repository.resendVerificationLink(email)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat mengirim email verifikasi'
      })
    }
  }

  async verifyEmail(token: string, email: string): Promise<void> {
    try {
      await this.repository.verifyEmail(token, email)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat verifikasi email'
      })
    }
  }

  async login(
    role: string,
    data: LoginPayload
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const userPayloadRequest = ZodValidation.validate(AuthValidation.LOGIN, data)
      const { accessToken, refreshToken } =
        role === 'user'
          ? await this.repository.login(userPayloadRequest)
          : await this.repository.loginAdmin(userPayloadRequest)
      return { accessToken, refreshToken }
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat login'
      })
    }
  }

  async refreshToken(
    refreshToken: string
  ): Promise<{ newAccessToken: string; newRefreshToken: string }> {
    try {
      const { newAccessToken, newRefreshToken } = await this.repository.refreshToken(refreshToken)
      return { newAccessToken, newRefreshToken }
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat refresh token'
      })
    }
  }

  async getProfile(userId: number): Promise<User> {
    try {
      return await this.repository.getProfile(userId)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat mengambil data profile'
      })
    }
  }

  async updateProfile(userId: number, data: UserUpdatePayload): Promise<User> {
    try {
      const userPayloadRequest = ZodValidation.validate(AuthValidation.UPDATE_PROFILE, data)
      return await this.repository.updateProfile(userId, userPayloadRequest)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat update profile'
      })
    }
  }

  async changePassword(email: string, data: ChangePasswordPayload): Promise<User> {
    try {
      const changePasswordPayload = ZodValidation.validate(AuthValidation.CHANGE_PASSWORD, data)
      return await this.repository.changePassword(email, changePasswordPayload)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat ubah password'
      })
    }
  }

  async sendTokenResetPassword(data: { email: string }): Promise<void> {
    try {
      const forgotPasswordPayload = ZodValidation.validate(AuthValidation.FORGOT_PASSWORD, data)
      await this.repository.sendTokenResetPassword(forgotPasswordPayload)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat kirim forgot password token'
      })
    }
  }

  async resetPassword(data: ResetPasswordPayload): Promise<User> {
    try {
      const resetPasswordPayload = ZodValidation.validate(AuthValidation.RESET_PASSWORD, data)
      return await this.repository.resetPassword(resetPasswordPayload)
    } catch (e) {
      throw CustomHandleError(e, {
        context: 'Error saat reset password'
      })
    }
  }
}
