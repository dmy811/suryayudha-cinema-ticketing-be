import { NextFunction, Request, Response, Router } from 'express'
import { snap } from '@infrastructure/config/midtrans'
import { prisma } from '@infrastructure/config/clientPrisma'
import { SeatStatus, TARGET_AUDIENCE, TicketStatus, TransactionStatus } from '@prisma/client'
import { generateRandomCode } from '@shared/helpers/randomCode'
import { ticketSuccessfullyCreatedTemplate } from '@shared/helpers/emailTemplate'
import { sendEmail } from '@infrastructure/config/nodemailer'
import { NotFoundException } from '@shared/error-handling/exceptions/not-found.exception'
import { logger } from '@shared/logger/logger'

export class WebhookController {
  private readonly webhookRouter: Router
  constructor() {
    this.webhookRouter = Router()
    this.initializeWebhookRoutes()
  }

  private initializeWebhookRoutes(): void {
    this.webhookRouter.post('/midtrans', this.midtransWebhookHandler)
  }

  private midtransWebhookHandler = async (req: Request, res: Response, next: NextFunction) => {
    logger.info({
      from: 'webhook:midtrans',
      message: 'Midtrans webhook received'
    })
    try {
      const notificationJson = req.body
      const statusResponse = await snap.transaction.notification(notificationJson)
      const orderId = statusResponse.order_id
      const paymentType = statusResponse.payment_type
      const transactionStatus = statusResponse.transaction_status
      const fraudStatus = statusResponse.fraud_status

      const transaction = await prisma.transaction.findFirst({
        where: {
          order_id: orderId
        },
        include: {
          user: true,
          transaction_items: {
            include: {
              schedule_seat: {
                include: {
                  schedule: {
                    include: {
                      movie: true,
                      studio: true
                    }
                  }
                }
              }
            }
          }
        }
      })

      if (!transaction) {
        throw new NotFoundException('Transaction not found for the given order_id')
      }

      if (transaction.status === 'settlement') {
        res.status(200).send('Transaction already settled.')
        return
      }

      if (transactionStatus == 'capture' || transactionStatus == 'settlement') {
        if (fraudStatus == 'accept') {
          const createdTickets = await prisma.$transaction(async (tx) => {
            await tx.transaction.update({
              where: { id: transaction.id },
              data: {
                status: TransactionStatus.settlement,
                payment_type: paymentType,
                status_sort_order: 3
              }
            })

            const scheduleSeatIds = transaction.transaction_items.map(
              (item) => item.schedule_seat_id
            )
            await tx.scheduleSeat.updateMany({
              where: {
                id: {
                  in: scheduleSeatIds
                }
              },
              data: {
                status: SeatStatus.booked
              }
            })

            const tickets = []
            for (const item of transaction.transaction_items) {
              const ticket = await tx.ticket.create({
                data: {
                  code: `TICKET-${transaction.id}-${item.id}-${generateRandomCode(13)}`,
                  status: TicketStatus.active,
                  transaction_item_id: item.id
                }
              })
              tickets.push(ticket)
            }

            const movieTitle =
              transaction.transaction_items[0]?.schedule_seat.schedule.movie.title || 'Film'
            const seatLabels = transaction.transaction_items
              .map((item) => item.seat_label)
              .join(', ')
            const notifDesc = `Terima kasih sudah melakukan pembayaran untuk tiket film ${movieTitle} pada kursi ${seatLabels}, silahkan cek e-tiket Anda di menu tiket saya atau di email Anda.`
            await tx.notification.create({
              data: {
                title: 'Pembayaran berhasil',
                description: notifDesc,
                target_audience: TARGET_AUDIENCE.spesific,
                notification_recipients: {
                  create: {
                    user_id: transaction.user_id
                  }
                }
              }
            })
            return tickets
          })

          logger.info({
            from: 'webhook:midtrans:kirim-email',
            message: 'preparing sending email tickets'
          })

          try {
            logger.info({
              from: 'webhook:midtrans:kirim-email',
              message: 'preparing more sending email tickets'
            })
            const schedule = transaction.transaction_items[0].schedule_seat.schedule
            const formatOptions: Intl.DateTimeFormatOptions = {
              weekday: 'long',
              day: 'numeric',
              month: 'long',
              hour: '2-digit',
              minute: '2-digit',
              timeZone: 'Asia/Jakarta'
            }

            const jadwalTayang = new Date(schedule.start_time).toLocaleString(
              'id-ID',
              formatOptions
            )
            const jadwalSelesai = new Date(schedule.finished_time).toLocaleString('id-ID', {
              hour: '2-digit',
              minute: '2-digit',
              timeZone: 'Asia/Jakarta'
            })
            for (const ticket of createdTickets) {
              const correspondingItem = transaction.transaction_items.find(
                (item) => item.id === ticket.transaction_item_id
              )

              if (correspondingItem) {
                const emailHtml = ticketSuccessfullyCreatedTemplate
                  .replace('{{namaUser}}', transaction.user.name)
                  .replace('{{judulFilm}}', schedule.movie.title)
                  .replace('{{studioName}}', schedule.studio.name)
                  .replace('{{jadwalTayang}}', `${jadwalTayang} WIB`)
                  .replace('{{jadwalSelesai}}', `~${jadwalSelesai} WIB`)
                  .replace('{{kursi}}', correspondingItem.seat_label)
                  .replace('{{kodeTiket}}', ticket.code)

                await sendEmail({
                  email: transaction.user.email,
                  subject: `E-Tiket Anda untuk ${schedule.movie.title} (Kursi ${correspondingItem.seat_label})`,
                  html: emailHtml
                })

                logger.info({
                  from: 'webhook:midtrans:kirim-email',
                  message: 'sending email tickets......'
                })
              }
            }
          } catch (emailError) {
            logger.error({
              from: 'webhook:midtrans:kirim-email',
              message: 'error saay mengirim email tiket'
            })
            console.error('Gagal mengirim email e-tiket:', emailError)
          }
        }
      }
      res.status(200).send('OK')
    } catch (e) {
      logger.error({ from: 'webhook:midtrans', message: `error: ${(e as Error).message}` })
      next(e)
    }
  }

  public getRoutes(): Router {
    return this.webhookRouter
  }
}
