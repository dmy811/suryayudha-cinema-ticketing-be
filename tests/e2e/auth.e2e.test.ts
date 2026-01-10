import { describe, it, expect, beforeEach, vi, beforeAll } from 'vitest'
import { sentEmails } from '../__mocks__/nodemailer'

vi.mock('nodemailer')
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
import { Routes } from '../../src/applications/routes/routes'
import App from '../../src/applications/app'
import { Application } from 'express'
import path from 'path'
import fs from 'fs'

let app: Application

let profilePicImageBuffer: Buffer
beforeAll(async () => {
  const filePath = path.join(__dirname, '../public/img/cinema-booking.png')
  profilePicImageBuffer = fs.readFileSync(filePath)
})
beforeEach(() => {
  const routes = new Routes()
  const appInstance = new App(routes)
  app = appInstance.getAppInstance()
})

describe('Auth E2E Flow (Success Case)', () => {
  it('(Success) POST /api/v1/auth/register -> Register User', async () => {
    const registerBody = {
      name: 'dims',
      email: 'dimasmukhtary@gmail.com',
      password: '00000000',
      passwordConfirmation: '00000000'
    }
    const res = await supertest(app).post('/api/v1/auth/register').send(registerBody).expect(201)

    expect(res.statusCode).toBe(201)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe(
      'Berhasil register dan verifikasi link telah dikirim ke email anda!, silahkan cek email untuk verifikasi'
    )
  })

  it('(Success) POST /api/v1/auth/resend-verification-token -> Resend Verification Link', async () => {
    const res = await supertest(app)
      .post('/api/v1/auth/resend-verification-token')
      .send({ email: 'dimasmukhtary@gmail.com' })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Link verifikasi berhasil dikirim ulang')
  })

  it('(Success) POST /api/v1/auth/login-admin -> Login Admin', async () => {
    const loginBody = {
      email: 'joker@gmail.com',
      password: 'jokerjoker'
    }
    const res = await supertest(app).post('/api/v1/auth/login-admin').send(loginBody).expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Login admin berhasil')
  })

  it('(Success) POST /api/v1/auth/login -> Login User', async () => {
    const loginBody = {
      email: 'dimasmukhtary@gmail.com',
      password: '00000000'
    }
    const res = await supertest(app).post('/api/v1/auth/login').send(loginBody).expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Login berhasil')
  })

  it('(Success) POST /api/v1/auth/google/callback ->  Google Callback', async () => {
    process.env.CLIENT_URL = 'http://localhost:3000'
    const res = await supertest(app).get('/api/v1/auth/google/callback')

    expect(res.statusCode).toBe(302)
    expect(res.headers.location).toBe('http://localhost:3000')
  })

  it('(Success) POST /api/v1/auth/facebook/callback -> Facebook Callback', async () => {
    process.env.CLIENT_URL = 'http://localhost:3000'
    const res = await supertest(app).get('/api/v1/auth/facebook/callback')

    expect(res.statusCode).toBe(302)
    expect(res.headers.location).toBe('http://localhost:3000')
  })

  it('(Success) POST /api/v1/auth/refresh -> Refresh Token', async () => {
    const res = await supertest(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', ['refreshToken=01983'])
      .expect(200)
    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Refresh token berhasil')
  })

  it('(Success) GET /api/v1/auth/profile -> Get Profile', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/profile')
      .set('Cookie', ['accessToken=01983'])
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Profile berhasil diambil')
    expect(res.body.data).toBeDefined()
  })

  it('(Success) PATCH /api/v1/auth/update-profile -> Update Profile', async () => {
    const res = await supertest(app)
      .patch('/api/v1/auth/update-profile')
      .set('Cookie', ['accessToken=01983'])
      .field('name', 'update name dims')
      .attach('profile_url', profilePicImageBuffer, 'cinema-booking.png')
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Profile berhasil diupdate')
    expect(res.body.data).toBeDefined()
  })

  it('(Success) PATCH /api/v1/auth/change-password -> Change Password', async () => {
    const res = await supertest(app)
      .patch('/api/v1/auth/change-password')
      .set('Cookie', ['accessToken=01983'])
      .send({
        oldPassword: '00000000',
        newPassword: '99999999',
        newPasswordConfirmation: '99999999'
      })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Password berhasil diubah')
    expect(res.body.data).toBeDefined()
  })

  it('(Success) POST /api/v1/auth/forgot-password -> Send Token Reset Password to Email', async () => {
    const res = await supertest(app)
      .post('/api/v1/auth/forgot-password')
      .send({
        email: 'dimasmukhtary@gmail.com'
      })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Token reset password berhasil dikirim')
  })

  it('(Success) POST /api/v1/auth/reset-password -> Reset Password', async () => {
    const res = await supertest(app)
      .post('/api/v1/auth/reset-password')
      .send({
        email: 'dimasmukhtary@gmail.com',
        passwordResetCode: 'reset-password',
        newPassword: '88888888',
        newPasswordConfirmation: '88888888'
      })
      .expect(200)

    expect(res.statusCode).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Password berhasil direset')
  })

  it('(Success) GET /api/v1/auth/check-auth -> Check is Authenticater', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/check-auth')
      .set('Cookie', ['accessToken=23842'])
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

describe('E2E Auth - Verify Email', () => {
  it('(Success) Register → Verify Email', async () => {
    await supertest(app)
      .post('/api/v1/auth/register')
      .send({
        name: 'Dimas',
        email: 'dimasmukhtary@gmail.com',
        password: 'password123'
      })
      .expect(201)
    expect(sentEmails.length).toBeGreaterThan(0)

    const lastEmail = sentEmails[sentEmails.length - 1]

    const tokenMatch = lastEmail.html.match(/token=([a-zA-Z0-9]+)/)
    expect(tokenMatch).not.toBeNull()

    const token = tokenMatch![1]

    const res = await supertest(app)
      .get(`/api/v1/auth/verify-email?token=${token}&email=dimasmukhtary@gmail.com`)
      .expect(200)

    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Email berhasil diverifikasi')
  })
})

describe('Auth E2E Flow (Failed Case)', () => {
  it('(Failed) POST /api/v1/auth/register -> Register User (email not provided)', async () => {
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

  it('(Failed) POST /api/v1/auth/register -> Register User (email already registered)', async () => {
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

  it('(Failed) POST /api/v1/auth/resend-verification-token -> Resend verification link (email not exists)', async () => {
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

  it('(Failed) GET /api/v1/auth/verify-email -> Verify Email (email not exists)', async () => {
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

  it('(Failed) GET /api/v1/auth/verify-email -> Verify Email (token is wrong)', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Token verifikasi salah')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) GET /api/v1/auth/verify-email -> Verify Email (email already verified)', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Email sudah terverifikasi')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) GET /api/v1/auth/verify-email -> Verify Email (token expired)', async () => {
    const res = await supertest(app)
      .get('/api/v1/auth/verify-email?token=978241&email=sample@gmail.com')
      .expect(400)

    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat verifikasi email: Token verifikasi sudah kadaluarsa')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) GET /api/v1/auth/login -> Login User (fields not provided)', async () => {
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

  it('(Failed) GET /api/v1/auth/login -> Login User (email not registered)', async () => {
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

  it('(Failed) GET /api/v1/auth/login -> Login User (admin trying to login in this route)', async () => {
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

  it('(Failed) GET /api/v1/auth/login -> Login User (password doenst match)', async () => {
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

  it('(Failed) POST /api/v1/auth/refresh -> Refresh Token (refresh token cookie doesnt exist in cookie', async () => {
    const res = await supertest(app).post('/api/v1/auth/refresh').expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat refresh token: Refresh token tidak ditemukan di cookies'
    )
    expect(res.body.errorCode).toBe('UNAUTHORIZED')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) POST /api/v1/auth/refresh -> Refresh Token (refresh token cookie doesnt exist in redis', async () => {
    const mockRefreshToken = 'qeqwq'
    const res = await supertest(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', [`refreshToken=${mockRefreshToken}`])
      .expect(401)

    expect(res.statusCode).toBe(401)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe(
      'Error saat refresh token: Refresh token di verifikasi oleh redis, akses ditolak karena refresh token tidak ada atau tidak valid'
    )
    expect(res.body.errorCode).toBe('UNAUTHORIZED')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) GET /api/v1/auth/login-admin -> Login Admin (fields not provided)', async () => {
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

  it('(Failed) GET /api/v1/auth/login-admin -> Login Admin (email not registered)', async () => {
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

  it('(Failed) GET /api/v1/auth/login-admin -> Login Admin (user trying to login in this route)', async () => {
    const requestBody = {
      email: 'joker@gmail.com',
      password: 'jokerjoker'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Login ini hanya untuk admin')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })

  it('(Failed) GET /api/v1/auth/login-admin -> Login Admin (password doenst match)', async () => {
    const requestBody = {
      email: 'dimasmukhtary@gmail.com',
      password: 'jokerjoker'
    }

    const res = await supertest(app).post('/api/v1/auth/login-admin').send(requestBody).expect(400)
    expect(res.statusCode).toBe(400)
    expect(res.body.success).toBe(false)
    expect(res.body.message).toBe('Error saat login: Password salah')
    expect(res.body.errorCode).toBe('BAD_REQUEST')
    expect(res.body.timeStamp).toEqual(expect.any(String))
  })
})
