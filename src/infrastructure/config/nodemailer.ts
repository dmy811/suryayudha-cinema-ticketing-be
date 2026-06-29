import nodemailer, { Transporter } from 'nodemailer'
import { logger } from '@shared/logger/logger'
import { InternalServerErrorException } from '@shared/error-handling/exceptions/internal-server.exception'

const transporter: Transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.USER_EMAIL,
    pass: process.env.APP_PASSWORD
  }
})

interface MailDatA {
  email: string
  subject: string
  html: string
}

export async function sendEmail(data: MailDatA): Promise<void> {
  try {
    await transporter.sendMail({
      from: process.env.USER_EMAIL,
      to: data.email,
      subject: data.subject,
      html: data.html
    })

    logger.info({
      from: 'nodemailer:kirim-email',
      message: 'success sending email......'
    })
  } catch (error: any) {
    logger.error({
      from: 'nodemailer:sendEmail',
      message: 'Error sending email',
      error
    })
    throw new InternalServerErrorException(error)
  }
}
