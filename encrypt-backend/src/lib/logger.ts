import pino from 'pino';
import { config } from '../config.js';

const sensitiveKeys = [
  'plaintext',
  'plain_text',
  'secret',
  'secretKey',
  'secret_key',
  'privateKey',
  'private_key',
  'apiKey',
  'api_key',
  'authorization',
  'password',
  'mnemonic',
  'seed',
  'x-internal-key',
  'X-Internal-Key',
  'internalKey',
  'internal_key',
  'unsignedTx',
  'signedTxBase64',
  'signature',
  'signatureBase64',
  'nek',
  'nekBase64',
];

export const logger = pino({
  level: config.LOG_LEVEL,
  redact: {
    paths: sensitiveKeys.flatMap((k) => [k, `*.${k}`, `*.*.${k}`]),
    censor: '[REDACTED]',
  },
  base: {
    service: 'encrypt-backend',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level: (label) => ({ level: label }),
  },
});
