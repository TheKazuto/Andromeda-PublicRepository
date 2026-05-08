import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { submitWireTransaction } from '../solana/instructions.js';
import { getTransactionStatus } from '../transaction/status.js';

export const transactionRoutes = new Hono();

const submitBody = z.object({
  signedTxBase64: z.string(),
  skipPreflight: z.boolean().optional(),
});

transactionRoutes.post('/submit', zValidator('json', submitBody), async (c) => {
  const b = c.req.valid('json');
  const signature = await submitWireTransaction(b.signedTxBase64, b.skipPreflight ?? false);
  return c.json({ signature });
});

transactionRoutes.get('/status/:signature', async (c) => {
  const status = await getTransactionStatus(c.req.param('signature'));
  return c.json(status);
});
