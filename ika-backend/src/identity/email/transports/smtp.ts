// Email — SMTP transport via nodemailer.

import nodemailer from 'nodemailer'
import type { EmailMessage, EmailTransport } from './index.js'

interface SmtpTransportInput {
  smtpUrl: string
  from: string
}

export function createSmtpEmailTransport(input: SmtpTransportInput): EmailTransport {
  const transporter = nodemailer.createTransport(input.smtpUrl)

  return {
    id: 'smtp',
    async send(message: EmailMessage): Promise<void> {
      await transporter.sendMail({
        from: input.from,
        to: message.to,
        subject: message.subject,
        html: message.html,
        text: message.text,
      })
    },
  }
}
