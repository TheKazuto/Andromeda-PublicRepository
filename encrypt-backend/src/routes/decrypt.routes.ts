import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import { buildRequestDecryption } from '../decrypt/request.js';
import { pollDecryption } from '../decrypt/poll.js';
import { decodeBase64 } from '../lib/validation.js';

export const decryptRoutes = new Hono();

const requestBody = z.object({
  payer: z.string(),
  requester: z.string(),
  ciphertextAccount: z.string(),
  decryptionRequestAccount: z.string(),
  requestIdBase64: z.string().optional(),
});

decryptRoutes.post('/request/prepare', zValidator('json', requestBody), async (c) => {
  const b = c.req.valid('json');
  const result = await buildRequestDecryption({
    payer: toAddress(b.payer),
    requester: toAddress(b.requester),
    ciphertextAccount: toAddress(b.ciphertextAccount),
    decryptionRequestAccount: toAddress(b.decryptionRequestAccount),
    requestId: b.requestIdBase64 ? decodeBase64(b.requestIdBase64) : undefined,
  });
  return c.json(result);
});

decryptRoutes.get('/poll/:account', async (c) => {
  const account = toAddress(c.req.param('account'));
  const result = await pollDecryption(account);
  return c.json(result);
});
