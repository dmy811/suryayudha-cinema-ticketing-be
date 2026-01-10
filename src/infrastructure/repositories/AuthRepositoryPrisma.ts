import { PrismaClient, User } from '@prisma/client'
import crypto from 'crypto'

import {
  RegisterPayload,
  LoginPayload,
  ProfileUpdatePayload,
  ChangePasswordPayload,
  ResetPasswordPayload,
  IAuthRepository
} from '@infrastructure/types/entities/AuthTypes'
import { NotFoundException } from '@shared/error-handling/exceptions/not-found.exception'
import { checkExists } from '@shared/helpers/checkExistingRow'
import { uploadImageToImageKit } from '../config/imagekit.config'
import { BadRequestException } from '@shared/error-handling/exceptions/bad-request.exception'
import { sendEmail } from '../config/nodemailer'
import { generateVerificationToken } from '@shared/helpers/generateVerificationToken'
import { hashPassword, verifyPassword } from '@shared/helpers/passwordEncrypt'
import { signJwt, verifyJwtToken } from '../config/jwt'
import { verificationEmailTemplate } from '@shared/helpers/emailTemplate'
import { logger } from '@shared/logger/logger'
import { setCache } from '@infrastructure/cache/setCache'
import { UnauthorizedException } from '@/shared/error-handling/exceptions/unauthorized.exception'
import { UserJwtPayload } from '@infrastructure/types/entities/UserTypes'
import redis from '@infrastructure/config/redis'

export class AuthRepositoryPrisma implements IAuthRepository {
  constructor(private readonly prisma: PrismaClient) {}
  async register(data: RegisterPayload): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { email: data.email } })
    if (user) {
      throw new BadRequestException(`Email ${data.email} sudah terdaftar`)
    }
    const verificationLink = `${process.env.CLIENT_URL}/verify-email?token=${data.verification_token}&email=${data.email}`
    const emailHtml = verificationEmailTemplate
      .replace('{{namaUser}}', data.name)
      .replace('{{verificationLink}}', verificationLink)

    logger.info({
      from: 'auth:register:repository',
      message: `Sending verification email to ${data.email}`
    })

    await sendEmail({
      email: data.email,
      subject: 'Verifikasi Akun Surya Yudha Cinema Anda',
      html: emailHtml
    })
    const { passwordConfirmation, ...prismaData } = data
    const userCreated = await this.prisma.user.create({
      data: {
        ...prismaData,
        password: await hashPassword(data.password)
      }
    })
    return userCreated
  }

  async resendVerificationLink(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email } })
    if (!user) {
      throw new NotFoundException(`User dengan email ${email} tidak ditemukan`)
    }
    const verificationToken = generateVerificationToken()
    const verificationTokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000)
    const verificationLink = `${process.env.CLIENT_URL}/verify-email?token=${verificationToken}&email=${email}`
    const emailHtml = verificationEmailTemplate
      .replace('{{namaUser}}', email)
      .replace('{{verificationLink}}', verificationLink)
    await sendEmail({
      email: email,
      subject: 'Link Verifikasi Akun Baru Anda',
      html: emailHtml
    })
    await this.prisma.user.update({
      where: {
        email
      },
      data: {
        verification_token: verificationToken,
        verification_token_expires_at: verificationTokenExpiresAt
      }
    })
  }

  async verifyEmail(token: string, email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: email
      }
    })
    if (!user) {
      throw new NotFoundException(`User dengan email ${email} tidak ditemukan`)
    }
    if (user.verification_token !== token) {
      throw new BadRequestException('Token verifikasi salah')
    }

    if (user.is_verified) {
      throw new BadRequestException('Email sudah terverifikasi')
    }

    if (user.verification_token_expires_at! < new Date()) {
      throw new BadRequestException('Token verifikasi sudah kadaluarsa')
    }
    await this.prisma.user.update({
      where: {
        email: email
      },
      data: {
        is_verified: true
      }
    })
  }

  async login(data: LoginPayload): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.prisma.user.findUnique({ where: { email: data.email } })
    if (!user) {
      throw new NotFoundException(`User dengan email ${data.email} tidak ditemukan`)
    }
    if (user.role !== 'user') {
      throw new BadRequestException('Login ini hanya untuk user')
    }
    const isPasswordValid = await verifyPassword(user.password, data.password)
    if (!isPasswordValid) {
      throw new BadRequestException('Password salah')
    }
    const accessToken = signJwt(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )
    const jti = crypto.randomUUID()
    const refreshToken = signJwt(
      { id: user.id, jti, name: user.name, email: user.email, role: user.role },
      'REFRESH_TOKEN_PRIVATE_KEY',
      { expiresIn: '7d' }
    )
    const refreshTokenKey = `refresh-token:${jti}`
    await setCache(refreshTokenKey, refreshToken, 60 * 60 * 24 * 7) // 7 days
    return { accessToken, refreshToken }
  }
  async loginAdmin(data: LoginPayload): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.prisma.user.findUnique({ where: { email: data.email } })
    if (!user) {
      throw new NotFoundException(`User dengan email ${data.email} tidak ditemukan`)
    }
    if (user.role !== 'admin') {
      throw new BadRequestException('Login ini hanya untuk admin')
    }
    const isPasswordValid = await verifyPassword(user.password, data.password)
    if (!isPasswordValid) {
      throw new BadRequestException('Password salah')
    }
    const accessToken = signJwt(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )
    const jti = crypto.randomUUID()
    const refreshToken = signJwt(
      { id: user.id, jti, name: user.name, email: user.email, role: user.role },
      'REFRESH_TOKEN_PRIVATE_KEY',
      { expiresIn: '7d' }
    )
    const refreshTokenKey = `refresh-token:${jti}`
    await setCache(refreshTokenKey, refreshToken, 60 * 60 * 24 * 7)
    return { accessToken, refreshToken }
  }

  async refreshToken(
    refreshToken: string
  ): Promise<{ newAccessToken: string; newRefreshToken: string }> {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token tidak ditemukan di cookies')
    }
    const payloadUser = verifyJwtToken(
      refreshToken,
      'REFRESH_TOKEN_PUBLIC_KEY'
    ) as UserJwtPayload & { jti: string }
    if (!payloadUser) {
      throw new UnauthorizedException(
        'Refresh token di verifikasi oleh jwt, dan akses ditolak karena refresh token tidak valid'
      )
    }
    const key = `refresh-token:${payloadUser.jti}`
    const refreshTokenFromRedis = await redis.get(key)
    if (!refreshTokenFromRedis) {
      throw new UnauthorizedException(
        'Refresh token di verifikasi oleh redis, akses ditolak karena refresh token tidak ada atau tidak valid'
      )
    }

    await redis.del(key)

    const newAccessToken = signJwt(
      {
        id: payloadUser.id,
        name: payloadUser.name,
        email: payloadUser.email,
        role: payloadUser.role
      },
      'ACCESS_TOKEN_PRIVATE_KEY',
      { expiresIn: '15m' }
    )
    const jti = crypto.randomUUID()
    const newRefreshToken = signJwt(
      {
        id: payloadUser.id,
        jti,
        name: payloadUser.name,
        email: payloadUser.email,
        role: payloadUser.role
      },
      'REFRESH_TOKEN_PRIVATE_KEY',
      { expiresIn: '7d' }
    )
    const refreshTokenKey = `refresh-token:${jti}`
    await setCache(refreshTokenKey, newRefreshToken, 60 * 60 * 24 * 7)
    return { newAccessToken, newRefreshToken }
  }

  async getProfile(userId: number): Promise<User> {
    const findUser = await this.prisma.user.findUnique({ where: { id: userId } })
    if (!findUser) {
      throw new NotFoundException(`User dengan id ${userId} tidak ditemukan`)
    }
    return findUser
  }

  async updateProfile(userId: number, data: ProfileUpdatePayload): Promise<User> {
    await checkExists(this.prisma.user, userId, 'User')
    let profileUrl: string | undefined
    if (data.profile_url) {
      const { url } = await uploadImageToImageKit('profile', '/users', data.profile_url)
      profileUrl = url
    }
    const dataUpdata: any = {
      ...data,
      ...(profileUrl && { profile_url: profileUrl })
    }
    return await this.prisma.user.update({ where: { id: userId }, data: dataUpdata })
  }

  async changePassword(email: string, data: ChangePasswordPayload): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { email } })
    if (!user) {
      throw new NotFoundException(`User dengan email ${email} tidak ditemukan`)
    }
    const isPasswordValid = await verifyPassword(user.password, data.oldPassword)
    if (!isPasswordValid) {
      throw new BadRequestException('Password lama salah')
    }
    const hash = await hashPassword(data.newPassword)
    return await this.prisma.user.update({
      where: { email },
      data: { password: hash }
    })
  }

  async sendTokenResetPassword(email: { email: string }): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email: email.email } })
    if (!user) {
      throw new NotFoundException(`User dengan email ${email.email} tidak ditemukan`)
    }
    const resetPasswordToken = generateVerificationToken()
    const resetPasswordTokenExpiresAt = new Date(Date.now() + 5 * 60 * 1000)
    await sendEmail({
      email: email.email,
      subject: 'Reset Password Token untuk reset password Anda',
      html: `<!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Token Reset Password</title>
        </head>
        <body
          style="
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
          "
        >
          <div
            style="
              background: linear-gradient(to right, #5f6fff, #5f6fff);
              padding: 20px;
              text-align: center;
            "
          >
            <h1 style="color: white; margin: 0">Token Reset Password</h1>
          </div>
          <div
            style="
              background-color: #f9f9f9;
              padding: 20px;
              border-radius: 0 0 5px 5px;
              box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            "
          >
            <p>Hallo</p>
            <p>Terimakasih atas kepercayaan anda untuk menggunakan layanan kami.</p>
            <div style="text-align: center; margin: 30px 0">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #5f6fff"
                >token=${resetPasswordToken}</span
              >
            </div>
            <p>Gunakan kode diatas untuk mereset password akun anda.</p>
            <p>
              Kode ini akan kedaluwarsa dalam 5 menit demi alasan keamanan, jadi pastikan anda verifikasi
              sebelum 5 menit!..
            </p>
            <p>Best regards,<br />Developer Team</p>
          </div>
          <div style="text-align: center; margin-top: 20px; color: #888; font-size: 0.8em">
            <p>Jika Anda tidak membuat akun dengan kami, harap abaikan email ini.</p>
          </div>
        </body>
      </html>
      , `
    })

    await this.prisma.user.update({
      where: { email: email.email },
      data: {
        reset_password_token: resetPasswordToken,
        reset_password_token_expires_at: resetPasswordTokenExpiresAt
      }
    })
  }

  async resetPassword(data: ResetPasswordPayload): Promise<User> {
    const user = await this.prisma.user.findUnique({ where: { email: data.email } })
    if (!user) {
      throw new NotFoundException(`User dengan email ${data.email} tidak ditemukan`)
    }
    if (data.passwordResetCode !== user.reset_password_token) {
      throw new BadRequestException('Token reset password salah')
    }
    if (user.reset_password_token_expires_at! < new Date()) {
      throw new BadRequestException('Token reset password sudah kadaluarsa')
    }

    const hash = await hashPassword(data.newPassword)
    return await this.prisma.user.update({
      where: { email: data.email },
      data: { password: hash, reset_password_token: null, reset_password_token_expires_at: null }
    })
  }
}
