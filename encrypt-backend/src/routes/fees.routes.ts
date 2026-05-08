/**
 * Routes wrapping the Fees group (disc 13..18):
 *   - create_deposit
 *   - top_up
 *   - withdraw
 *   - request_withdraw
 *   - reimburse
 *   - update_config_fees
 */

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import {
  buildCreateDepositIx,
  buildTopUpIx,
  buildWithdrawIx,
  buildRequestWithdrawIx,
  buildReimburseIx,
  buildUpdateConfigFeesIx,
} from '../graph/fees.js';
import { deriveDepositPda } from '../graph/ciphertextAccounts.js';
import { buildUnsignedTransaction } from '../solana/instructions.js';
import { decodeBase64 } from '../lib/validation.js';
import { serializeUnsignedTx } from '../lib/responses.js';

export const feesRoutes = new Hono();

const createDepositBody = z.object({
  payer: z.string(),
  owner: z.string(),
  initialLamports: z.union([z.string(), z.number()]).transform((v) => BigInt(v)).optional(),
});

feesRoutes.post('/deposit/create/prepare', zValidator('json', createDepositBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const owner = toAddress(b.owner);
  const [depositPda] = await deriveDepositPda(owner);
  const ix = buildCreateDepositIx({
    payer,
    owner,
    depositPda,
    initialLamports: b.initialLamports,
  });
  const tx = await buildUnsignedTransaction({ feePayer: payer, instructions: [ix] });
  return c.json({ depositPda: String(depositPda), unsignedTx: serializeUnsignedTx(tx) });
});

const lamportsBody = z.object({
  payer: z.string(),
  owner: z.string(),
  lamports: z.union([z.string(), z.number()]).transform((v) => BigInt(v)),
});

feesRoutes.post('/deposit/top-up/prepare', zValidator('json', lamportsBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const owner = toAddress(b.owner);
  const [depositPda] = await deriveDepositPda(owner);
  const ix = buildTopUpIx({ payer, depositPda, lamports: b.lamports });
  const tx = await buildUnsignedTransaction({ feePayer: payer, instructions: [ix] });
  return c.json({ depositPda: String(depositPda), unsignedTx: serializeUnsignedTx(tx) });
});

const withdrawBody = z.object({
  owner: z.string(),
  destination: z.string(),
  lamports: z.union([z.string(), z.number()]).transform((v) => BigInt(v)),
});

feesRoutes.post('/deposit/withdraw/prepare', zValidator('json', withdrawBody), async (c) => {
  const b = c.req.valid('json');
  const owner = toAddress(b.owner);
  const destination = toAddress(b.destination);
  const [depositPda] = await deriveDepositPda(owner);
  const ix = buildWithdrawIx({ owner, depositPda, destination, lamports: b.lamports });
  const tx = await buildUnsignedTransaction({ feePayer: owner, instructions: [ix] });
  return c.json({ depositPda: String(depositPda), unsignedTx: serializeUnsignedTx(tx) });
});

feesRoutes.post('/deposit/request-withdraw/prepare', zValidator('json', lamportsBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const owner = toAddress(b.owner);
  const [depositPda] = await deriveDepositPda(owner);
  const ix = buildRequestWithdrawIx({ owner, depositPda, lamports: b.lamports });
  const tx = await buildUnsignedTransaction({ feePayer: payer, instructions: [ix] });
  return c.json({ depositPda: String(depositPda), unsignedTx: serializeUnsignedTx(tx) });
});

const reimburseBody = z.object({
  authority: z.string(),
  ownerOfDeposit: z.string(),
  lamports: z.union([z.string(), z.number()]).transform((v) => BigInt(v)),
});

feesRoutes.post('/deposit/reimburse/prepare', zValidator('json', reimburseBody), async (c) => {
  const b = c.req.valid('json');
  const authority = toAddress(b.authority);
  const owner = toAddress(b.ownerOfDeposit);
  const [depositPda] = await deriveDepositPda(owner);
  const ix = buildReimburseIx({ authority, depositPda, lamports: b.lamports });
  const tx = await buildUnsignedTransaction({ feePayer: authority, instructions: [ix] });
  return c.json({ depositPda: String(depositPda), unsignedTx: serializeUnsignedTx(tx) });
});

const updateConfigBody = z.object({
  authority: z.string(),
  configAccount: z.string(),
  configBytesBase64: z.string(),
});

feesRoutes.post('/config/update/prepare', zValidator('json', updateConfigBody), async (c) => {
  const b = c.req.valid('json');
  const authority = toAddress(b.authority);
  const ix = buildUpdateConfigFeesIx({
    authority,
    configAccount: toAddress(b.configAccount),
    configBytes: decodeBase64(b.configBytesBase64),
  });
  const tx = await buildUnsignedTransaction({ feePayer: authority, instructions: [ix] });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});
