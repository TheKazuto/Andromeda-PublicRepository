import { randomBytes } from 'node:crypto'
import { logger } from './logger.js'

const ALLOWED_VERBATIM: RegExp[] = [
  /^Invalid [\w\s]+$/i,
  /^Missing [\w\s]+$/i,
  /^Unauthorized:/i,
  /^Forbidden:/i,
  /^Too many requests/i,
  /^Recovery [\w\s\d-]+ expired$/i,
  /^Quorum threshold not met$/i,
  /^Daily limit exceeded$/i,
  /^Destination not in whitelist$/i,
  /^Cooldown still active$/i,
  /^Policy already revoked$/i,
  /^dWallet not found$/i,
  /^MessageApproval not pending$/i,
]

export interface SafeErrorPayload {
  message: string
  traceId: string
}

function generateTraceId(): string {
  return `trc_${randomBytes(8).toString('hex')}`
}

function isVerbatimSafe(message: string): boolean {
  if (!message || message.length > 200) return false
  return ALLOWED_VERBATIM.some((p) => p.test(message))
}

export function sanitizeError(
  context: string,
  error: unknown,
  options: { fallbackMessage?: string } = {},
): SafeErrorPayload {
  const traceId = generateTraceId()
  const fallback = options.fallbackMessage ?? 'Internal server error'

  if (error instanceof Error) {
    logger.error({ traceId, context, stack: error.stack }, error.message)
    if (isVerbatimSafe(error.message)) {
      return { message: error.message, traceId }
    }
    return { message: fallback, traceId }
  }

  logger.error({ traceId, context, error }, 'non-error throw')
  return { message: fallback, traceId }
}
