import { describe, it, expect, beforeEach, vi, beforeAll } from 'vitest'
import { sentEmails } from '../__mocks__/nodemailer'

vi.mock('nodemailer')
vi.mock('passport', () => {
  return {
    default: {
      use: vi.fn(),
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
import { Routes } from '../../src/applications/routes/routes'
import App from '../../src/applications/app'
import { Application } from 'express'
import path from 'path'
import fs from 'fs'

let app: Application

let profilePicImageBuffer: Buffer
beforeAll(async () => {
  const filePath = path.join(__dirname, '../../public/img/cinema-booking.png')
  profilePicImageBuffer = fs.readFileSync(filePath)
})
beforeEach(() => {
  const routes = new Routes()
  const appInstance = new App(routes)
  app = appInstance.getAppInstance()
})

describe('E2E Auth - Flow to Make account', () => {
  it('(Success) -> Register user -> Verify email', async () => {
    const registerBody = {
      name: 'dims',
      email: 'dimasmukhtary@gmail.com',
      password: '00000000',
      passwordConfirmation: '00000000'
    }
    const responseRegister = await supertest(app)
      .post('/api/v1/auth/register')
      .send(registerBody)
      .expect(201)

    expect(sentEmails.length).toBeGreaterThan(0)

    const lastEmail = sentEmails[sentEmails.length - 1]

    const tokenMatch = lastEmail.html.match(/token=([0-9]{6})/)
    expect(tokenMatch).not.toBeNull()

    const token = tokenMatch![1]

    const responseVerifyEmail = await supertest(app)
      .get(`/api/v1/auth/verify-email?token=${token}&email=dimasmukhtary@gmail.com`)
      .expect(200)

    expect(responseRegister.statusCode).toBe(201)
    expect(responseRegister.body.success).toBe(true)
    expect(responseRegister.body.message).toBe(
      'Berhasil register dan verifikasi link telah dikirim ke email anda!, silahkan cek email untuk verifikasi'
    )

    expect(responseVerifyEmail.statusCode).toBe(200)
    expect(responseVerifyEmail.body.success).toBe(true)
    expect(responseVerifyEmail.body.message).toBe('Email berhasil diverifikasi')
  })
})

describe('E2E Auth - Flow to user get and update their profile', () => {
  it('(Success) -> Login(Authenticated) First -> Get profile -> Update profile', async () => {
    const responseLogin = await supertest(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'dimasmukhtary@gmail.com',
        password: '00000000'
      })
      .expect(200)

    const cookies = responseLogin.headers['set-cookie']
    expect(cookies).toBeDefined()

    const responseGetProfile = await supertest(app)
      .get('/api/v1/auth/profile')
      .set('Cookie', cookies)
      .expect(200)

    const responseUpdateProfile = await supertest(app)
      .patch('/api/v1/auth/update-profile')
      .set('Cookie', cookies)
      .field('name', 'update name dims')
      .attach('profile_url', profilePicImageBuffer, 'cinema-booking.png')
      .expect(200)

    expect(responseLogin.statusCode).toBe(200)
    expect(responseLogin.body.success).toBe(true)
    expect(responseLogin.body.message).toBe('Login berhasil')

    expect(responseGetProfile.statusCode).toBe(200)
    expect(responseGetProfile.body.success).toBe(true)
    expect(responseGetProfile.body.message).toBe('Profile berhasil diambil')
    expect(responseGetProfile.body.data).toBeDefined()

    expect(responseUpdateProfile.statusCode).toBe(200)
    expect(responseUpdateProfile.body.success).toBe(true)
    expect(responseUpdateProfile.body.message).toBe('Profile berhasil diupdate')
    expect(responseUpdateProfile.body.data).toBeDefined()
  })
})

describe('E2E Auth - Flow to resend verification link and verify email', () => {
  it('(Success) -> Resend verification link -> Verify email', async () => {
    const responseResendVerificationLink = await supertest(app)
      .post('/api/v1/auth/resend-verification-token')
      .send({ email: 'dimasmukhtary@gmail.com' })
      .expect(200)

    expect(sentEmails.length).toBeGreaterThan(0)

    const lastEmail = sentEmails[sentEmails.length - 1]

    const tokenMatch = lastEmail.html.match(/token=([0-9]{6})/)
    expect(tokenMatch).not.toBeNull()

    const token = tokenMatch![1]

    const responseVerifyEmail = await supertest(app)
      .get(`/api/v1/auth/verify-email?token=${token}&email=dimasmukhtary@gmail.com`)
      .expect(200)

    expect(responseResendVerificationLink.statusCode).toBe(200)
    expect(responseResendVerificationLink.body.success).toBe(true)
    expect(responseResendVerificationLink.body.message).toBe(
      'Link verifikasi berhasil dikirim ulang'
    )

    expect(responseVerifyEmail.statusCode).toBe(200)
    expect(responseVerifyEmail.body.success).toBe(true)
    expect(responseVerifyEmail.body.message).toBe('Email berhasil diverifikasi')
  })
})

describe('E2E Auth - Flow for oauth google and facebook to calling callback handler', () => {
  it('(Success) ->  Google Callback', async () => {
    process.env.CLIENT_URL = 'http://localhost:3000'
    const res = await supertest(app).get('/api/v1/auth/google/callback')

    expect(res.statusCode).toBe(302)
    expect(res.headers.location).toBe('http://localhost:3000')
  })

  it('(Success) -> Facebook Callback', async () => {
    process.env.CLIENT_URL = 'http://localhost:3000'
    const res = await supertest(app).get('/api/v1/auth/facebook/callback')

    expect(res.statusCode).toBe(302)
    expect(res.headers.location).toBe('http://localhost:3000')
  })
})

describe('E2E Auth - Flow to rotate refresh token', () => {
  it('(Success) -> Login Admin/User -> Refresh token', async () => {
    const loginBody = {
      email: 'joker@gmail.com',
      password: 'jokerjoker'
    }
    const responseLogin = await supertest(app)
      .post('/api/v1/auth/login-admin')
      .send(loginBody)
      .expect(200)

    const cookies = responseLogin.headers['set-cookie']
    expect(cookies).toBeDefined()

    const responseRefreshToken = await supertest(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', cookies)
      .expect(200)

    expect(responseLogin.statusCode).toBe(200)
    expect(responseLogin.body.success).toBe(true)
    expect(responseLogin.body.message).toBe('Login admin berhasil')

    expect(responseRefreshToken.statusCode).toBe(200)
    expect(responseRefreshToken.body.success).toBe(true)
    expect(responseRefreshToken.body.message).toBe('Refresh token berhasil')
  })
})

describe('E2E Auth - Flow to change password', () => {
  it('(Success) -> Login/Authenticate First -> Change Password', async () => {
    const responseLogin = await supertest(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'dimasmukhtary@gmail.com',
        password: '00000000'
      })
      .expect(200)

    const cookies = responseLogin.headers['set-cookie']
    expect(cookies).toBeDefined()

    const responseChangePassword = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', cookies)
      .send({
        oldPassword: '00000000',
        newPassword: '99999999',
        newPasswordConfirmation: '99999999'
      })
      .expect(200)

    expect(responseLogin.statusCode).toBe(200)
    expect(responseLogin.body.success).toBe(true)
    expect(responseLogin.body.message).toBe('Login berhasil')

    expect(responseChangePassword.statusCode).toBe(200)
    expect(responseChangePassword.body.success).toBe(true)
    expect(responseChangePassword.body.message).toBe('Password berhasil diubah')
    expect(responseChangePassword.body.data).toBeDefined()
  })
})

describe('E2E Auth - Flow to reset password', () => {
  it('(Success) -> Send token reset password -> Reset password', async () => {
    const responseSendTokenResetPassword = await supertest(app)
      .post('/api/v1/auth/forgot-password')
      .send({
        email: 'dimasmukhtary@gmail.com'
      })
      .expect(200)

    expect(sentEmails.length).toBeGreaterThan(0)

    const lastEmail = sentEmails[sentEmails.length - 1]

    const tokenMatch = lastEmail.html.match(/token=([0-9]{6})/)
    expect(tokenMatch).not.toBeNull()

    const token = tokenMatch![1]

    const responseResetPassword = await supertest(app)
      .post('/api/v1/auth/reset-password')
      .send({
        email: 'dimasmukhtary@gmail.com',
        passwordResetCode: token,
        newPassword: '88888888',
        newPasswordConfirmation: '88888888'
      })
      .expect(200)

    expect(responseSendTokenResetPassword.statusCode).toBe(200)
    expect(responseSendTokenResetPassword.body.success).toBe(true)
    expect(responseSendTokenResetPassword.body.message).toBe(
      'Token reset password berhasil dikirim'
    )

    expect(responseResetPassword.statusCode).toBe(200)
    expect(responseResetPassword.body.success).toBe(true)
    expect(responseResetPassword.body.message).toBe('Password berhasil direset')
  })
})

describe('Auth E2E - Others', () => {
  it('(Success) GET /api/v1/auth/check-auth -> Check is Authenticater', async () => {
    const responseLogin = await supertest(app).post('/api/v1/auth/login').send({
      email: 'dimasmukhtary@gmail.com',
      password: '88888888'
    })

    const cookies = responseLogin.headers['set-cookie']
    expect(cookies).toBeDefined()

    const res = await supertest(app)
      .get('/api/v1/auth/check-auth')
      .set('Cookie', cookies)
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Autentikasi berhasil')
  })

  it('(Success) POST /api/v1/auth/logout -> Logout', async () => {
    const res = await supertest(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', ['refreshToken=12312321'])
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Logout berhasil')
  })
})

describe('Auth E2E Flow (Failed Case)', () => {
  it('(Failed) -> Register User (email not provided)', async () => {
    const registerBody = {
      name: 'dims',
      password: '00000000',
      passwordConfirmation: '00000000'
    }
    const res = await supertest(app).post('/api/v1/auth/register').send(registerBody).expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat membuat user: Email harus diisi')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Register User (email already registered)', async () => {
    const registerBody = {
      name: 'dims',
      email: 'joker@gmail.com',
      password: '00000000',
      passwordConfirmation: '00000000'
    }
    const res = await supertest(app).post('/api/v1/auth/register').send(registerBody).expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat membuat user: Email joker@gmail.com sudah terdaftar')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Resend verification link (email not exists)', async () => {
    const res = await supertest(app)
      .post('/api/v1/auth/resend-verification-token')
      .send({ email: 'sample@gmail.com' })
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat mengirim email verifikasi: User dengan email sample@gmail.com tidak ditemukan'
    )
    expect(res.body.errorCode).toBe('NOT_FOUND')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Verify Email (email not exists)', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(404)

    expect(res.statusCode).toBe(404)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat verifikasi email: User dengan email sample@gmail.com tidak ditemukan'
    )
    expect(res.body.errorCode).toBe('NOT_FOUND')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Verify Email (token is wrong)', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=dimasmukhtary@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Token verifikasi salah')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Verify Email (email already verified)', async () => {
    await supertest(app)
      .post('/api/v1/auth/resend-verification-token')
      .send({ email: 'dimasmukhtary@gmail.com' })
      .expect(200)

    expect(sentEmails.length).toBeGreaterThan(0)

    const lastEmail = sentEmails[sentEmails.length - 1]

    const tokenMatch = lastEmail.html.match(/token=([0-9]{6})/)
    expect(tokenMatch).not.toBeNull()

    const token = tokenMatch![1]

    const res = await supertest(app)
      .get(`/api/v1/auth/verify-email?token=${token}&email=sample@gmail.com`)
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Email sudah terverifikasi')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login User (fields not provided)', async () => {
    const requestBody = {
      email: 'sample@gmail.com'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password harus diisi')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login User (email not registered)', async () => {
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
    expect(res.body.errorCode).toBe('NOT_FOUND')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login User (admin trying to login in this route)', async () => {
    const requestBody = {
      email: 'joker@gmail.com',
      password: 'jokerjoker'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Login ini hanya untuk user')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login User (password doenst match)', async () => {
    const requestBody = {
      email: 'dimasmukhtary@gmail.com',
      password: 'jokerjoker'
    }

    const res = await supertest(app).post('/api/v1/auth/login').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password salah')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Refresh Token (refresh token cookie doesnt exist in cookie', async () => {
    const res = await supertest(app).post('/api/v1/auth/refresh').expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat refresh token: Refresh token tidak ditemukan di cookies'
    )
    expect(res.body.errorCode).toBe('UNAUTHORIZED')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login Admin (fields not provided)', async () => {
    const requestBody = {
      email: 'sample@gmail.com'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password harus diisi')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login Admin (email not registered)', async () => {
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
    expect(res.body.errorCode).toBe('NOT_FOUND')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login Admin (user trying to login in this route)', async () => {
    const requestBody = {
      email: 'dimasmukhtary@gmail.com',
      password: 'jokerjoker'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Login ini hanya untuk admin')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) -> Login Admin (password doenst match)', async () => {
    const requestBody = {
      email: 'joker@gmail.com',
      password: '00000000000'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password salah')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })
})
