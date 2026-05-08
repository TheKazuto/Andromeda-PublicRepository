// Email — transport abstraction.

import { getIdentityConfig, type EmailTransportName } from '../../config.js'
import { createMemoryEmailTransport, type MemoryEmailTransport } from './memory.js'
import { createSmtpEmailTransport } from './smtp.js'

export interface EmailMessage {
  to: string
  subject: string
  html: string
  text: string
}

export interface EmailTransport {
  readonly id: EmailTransportName
  send(message: EmailMessage): Promise<void>
}

let cachedTransport: EmailTransport | null = null
let cachedSignature: string | null = null

function buildTransport(): EmailTransport {
  const config = getIdentityConfig()
  const transport = config.email.transport
  switch (transport) {
    case 'smtp':
      if (!config.email.smtpUrl) {
        throw new Error('IKA_IDENTITY_EMAIL_SMTP_URL is required for transport=smtp')
      }
      if (!config.email.from) {
        throw new Error('IKA_IDENTITY_EMAIL_FROM is required for email transport')
      }
      return createSmtpEmailTransport({ smtpUrl: config.email.smtpUrl, from: config.email.from })
    case 'memory':
      return createMemoryEmailTransport()
  }
}

function transportSignature(): string {
  const config = getIdentityConfig()
  return [config.email.transport, config.email.smtpUrl ?? '', config.email.from ?? ''].join('|')
}

export function getEmailTransport(): EmailTransport {
  const signature = transportSignature()
  if (cachedTransport && cachedSignature === signature) {
    return cachedTransport
  }
  cachedTransport = buildTransport()
  cachedSignature = signature
  return cachedTransport
}

export function _setEmailTransport(transport: EmailTransport): void {
  cachedTransport = transport
  cachedSignature = transportSignature()
}

export function _resetEmailTransportCache(): void {
  cachedTransport = null
  cachedSignature = null
}

export type { MemoryEmailTransport }
