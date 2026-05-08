import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import { buildEmitEventIx } from '../graph/authority.js';
import { buildUnsignedTransaction } from '../solana/instructions.js';
import { decodeBase64 } from '../lib/validation.js';
import { rpc } from '../solana/connection.js';
import { Errors } from '../lib/errors.js';
import { serializeUnsignedTx } from '../lib/responses.js';
import type { Signature } from '@solana/kit';

export const eventsRoutes = new Hono();

const emitBody = z.object({
  emitter: z.string(),
  payerOverride: z.string().optional(),
  eventBytesBase64: z.string(),
});

eventsRoutes.post('/emit/prepare', zValidator('json', emitBody), async (c) => {
  const b = c.req.valid('json');
  const emitter = toAddress(b.emitter);
  const ix = buildEmitEventIx({
    emitter,
    eventBytes: decodeBase64(b.eventBytesBase64),
  });
  const tx = await buildUnsignedTransaction({
    feePayer: b.payerOverride ? toAddress(b.payerOverride) : emitter,
    instructions: [ix],
    computeUnitLimit: 100_000,
  });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

eventsRoutes.get('/by-signature/:signature', async (c) => {
  const sig = c.req.param('signature') as Signature;
  try {
    const tx = await rpc
      .getTransaction(sig, { maxSupportedTransactionVersion: 0, encoding: 'json' })
      .send();
    if (!tx) return c.json({ found: false });
    return c.json({
      found: true,
      slot: Number(tx.slot),
      logs: tx.meta?.logMessages ?? [],
    });
  } catch (err) {
    throw Errors.solanaRpc('failed to fetch transaction', err);
  }
});
