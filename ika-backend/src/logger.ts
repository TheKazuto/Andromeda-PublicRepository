import pino from 'pino'

const level = process.env.LOG_LEVEL ?? 'info'
const isDev = process.env.NODE_ENV !== 'production'

export const logger = pino({
  level,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers["x-api-key"]',
      'req.headers["x-service-api-key"]',
      '*.password',
      '*.secret',
      '*.privateKey',
      '*.private_key',
      '*.apiKey',
      '*.api_key',
      '*.token',
      '*.refreshToken',
      '*.accessToken',
      '*.signature',
      '*.user_signature',
      '*.email',
      '*.smtp_url',
    ],
    censor: '[REDACTED]',
  },
  ...(isDev
    ? {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'SYS:standard' },
        },
      }
    : {}),
})
