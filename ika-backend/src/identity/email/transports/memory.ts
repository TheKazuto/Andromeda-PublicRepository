// Email — in-memory transport for development and tests.

import type { EmailMessage, EmailTransport } from './index.js'

export interface MemoryEmailTransport extends EmailTransport {
  readonly id: 'memory'
  readonly messages: ReadonlyArray<EmailMessage>
  clear(): void
}

const DEFAULT_BUFFER = 200

export function createMemoryEmailTransport(buffer = DEFAULT_BUFFER): MemoryEmailTransport {
  const messages: EmailMessage[] = []

  return {
    id: 'memory',
    get messages() {
      return messages.slice()
    },
    async send(message: EmailMessage): Promise<void> {
      messages.push(message)
      if (messages.length > buffer) {
        messages.shift()
      }
    },
    clear() {
      messages.length = 0
    },
  }
}
