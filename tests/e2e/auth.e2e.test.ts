import supertest from 'supertest'
import { describe, it, expect, beforeEach } from 'vitest'
import { Routes } from '../../src/applications/routes/routes'
import App from '../../src/applications/app'
import { Application } from 'express'

describe('Auth E2E Flow', () => {
  let app: Application
  beforeEach(() => {
    const routes = new Routes()
    const appInstance = new App(routes)
    app = appInstance.getAppInstance()
  })
  it('1. (Success) -> Register User', async () => {
    const registerBody = {
      name: 'dims',
      email: 'sample@gmail.com',
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
})
