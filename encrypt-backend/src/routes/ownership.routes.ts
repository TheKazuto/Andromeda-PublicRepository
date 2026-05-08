/**
 * Ownership routes (disc 7..9): transfer, copy, make_public.
 */

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import {
  buildTransferCiphertextIx,
  buildCopyCiphertextIx,
  buildMakePublicIx,
} from '../graph/ownership.js';
import { buildUnsignedTransaction } from '../solana/instructions.js';
import { serializeUnsignedTx } from '../lib/responses.js';

export const ownershipRoutes = new Hono();

const transferBody = z.object({
  authority: z.string(),
  ciphertextAccount: z.string(),
  newOwner: z.string(),
});

ownershipRoutes.post('/transfer/prepare', zValidator('json', transferBody), async (c) => {
  const b = c.req.valid('json');
  const authority = toAddress(b.authority);
  const ix = buildTransferCiphertextIx({
    authority,
    ciphertextAccount: toAddress(b.ciphertextAccount),
    newOwner: toAddress(b.newOwner),
  });
  const tx = await buildUnsignedTransaction({ feePayer: authority, instructions: [ix] });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

const copyBody = z.object({
  payer: z.string(),
  authority: z.string(),
  source: z.string(),
  destination: z.string(),
});

ownershipRoutes.post('/copy/prepare', zValidator('json', copyBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const ix = buildCopyCiphertextIx({
    payer,
    authority: toAddress(b.authority),
    source: toAddress(b.source),
    destination: toAddress(b.destination),
  });
  const tx = await buildUnsignedTransaction({ feePayer: payer, instructions: [ix] });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

const makePublicBody = z.object({
  authority: z.string(),
  ciphertextAccount: z.string(),
});

ownershipRoutes.post('/make-public/prepare', zValidator('json', makePublicBody), async (c) => {
  const b = c.req.valid('json');
  const authority = toAddress(b.authority);
  const ix = buildMakePublicIx({
    authority,
    ciphertextAccount: toAddress(b.ciphertextAccount),
  });
  const tx = await buildUnsignedTransaction({ feePayer: authority, instructions: [ix] });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});
