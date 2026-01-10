import { vi } from 'vitest'

export const sentEmails: any[] = []

export default {
  createTransport: vi.fn(() => ({
    sendMail: vi.fn((mailOptions) => {
      sentEmails.push(mailOptions)
      return Promise.resolve(true)
    })
  }))
}
