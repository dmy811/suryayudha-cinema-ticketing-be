import { Prisma } from '@prisma/client'
import { ConflictException } from '../exceptions/conflict.exception'
import { NotFoundException } from '../exceptions/not-found.exception'
import { HttpException } from '../exceptions/http.exception'
import { BadRequestException } from '../exceptions/bad-request.exception'
import { InternalServerErrorException } from '../exceptions/internal-server.exception'
import { ZodError } from 'zod'

type HandleErrorOptions = {
  context?: string
}
export function CustomHandleError(error: any, options: HandleErrorOptions = {}): HttpException {
  const { context = '[Application]' } = options
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    switch (error.code) {
      case 'P2002':
        return new ConflictException(`${context}: ${error.message}`)
      case 'P2025':
        return new NotFoundException(`${context}: ${error.message}`)
      default:
        return new HttpException(
          500,
          `${context}: ${error.message}`,
          'PRISMA_CLIENT_KNOWN_REQUEST_ERROR'
        )
    }
  }

  if (error instanceof Prisma.PrismaClientValidationError) {
    return new BadRequestException(`${context}: ${error.message}`)
  }

  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return new InternalServerErrorException(`${context}: ${error.message}`)
  }

  if (error instanceof ZodError) {
    const messages = error.errors.map((e) => e.message).join(', ')
    return new BadRequestException(`${context}: ${messages}`)
  }

  return new HttpException(error.statusCode, `${context}: ${error.message}`, error.errorCode)
}
