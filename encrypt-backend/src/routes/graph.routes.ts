import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import {
  buildExecuteGraphIx,
  buildRegisterGraphIx,
  buildExecuteRegisteredGraphIx,
  buildCommitCiphertextIx,
} from '../graph/builder.js';
import { buildUnsignedTransaction, submitWireTransaction } from '../solana/instructions.js';
import { Base64String, decodeBase64, decodeBase64Sized } from '../lib/validation.js';
import { registerOperation, listOperations, getOperation } from '../dsl/operations.js';
import { Errors } from '../lib/errors.js';
import { getTransactionStatus } from '../transaction/status.js';
import { serializeUnsignedTx } from '../lib/responses.js';

export const graphRoutes = new Hono();

const executeBody = z.object({
  payer: z.string(),
  signer: z.string(),
  configAccount: z.string(),
  depositAccount: z.string(),
  networkEncryptionKey: z.string(),
  graphBytesBase64: Base64String,
  inputCiphertexts: z.array(z.string()).min(1),
  outputCiphertexts: z.array(z.string()).min(1),
  computeUnitLimit: z.number().int().positive().max(1_400_000).optional(),
});

graphRoutes.post('/execute/prepare', zValidator('json', executeBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const ix = buildExecuteGraphIx({
    payer,
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    caller: toAddress(b.signer),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    graphBytes: decodeBase64(b.graphBytesBase64),
    inputCiphertexts: b.inputCiphertexts.map(toAddress),
    outputCiphertexts: b.outputCiphertexts.map(toAddress),
  });

  const tx = await buildUnsignedTransaction({
    feePayer: payer,
    instructions: [ix],
    computeUnitLimit: b.computeUnitLimit ?? 1_400_000,
  });

  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

const registerBody = z.object({
  payer: z.string(),
  authority: z.string(),
  registrar: z.string().optional(),
  graphAccount: z.string(),
  graphHashBase64: Base64String,
  graphBytesBase64: Base64String,
  bump: z.number().int().min(0).max(255),
});

graphRoutes.post('/register/prepare', zValidator('json', registerBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const ix = buildRegisterGraphIx({
    payer,
    registrar: toAddress(b.registrar ?? b.authority),
    graphAccount: toAddress(b.graphAccount),
    graphHash: decodeBase64Sized(b.graphHashBase64, 32, 'graphHashBase64'),
    graphBytes: decodeBase64(b.graphBytesBase64),
    bump: b.bump,
  });
  const tx = await buildUnsignedTransaction({
    feePayer: payer,
    instructions: [ix],
    computeUnitLimit: 800_000,
  });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

const execRegBody = z.object({
  payer: z.string(),
  signer: z.string(),
  configAccount: z.string(),
  depositAccount: z.string(),
  networkEncryptionKey: z.string(),
  graphAccount: z.string(),
  inputCiphertexts: z.array(z.string()).min(1),
  outputCiphertexts: z.array(z.string()).min(1),
});

graphRoutes.post('/execute-registered/prepare', zValidator('json', execRegBody), async (c) => {
  const b = c.req.valid('json');
  const payer = toAddress(b.payer);
  const ix = buildExecuteRegisteredGraphIx({
    payer,
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    caller: toAddress(b.signer),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    graphAccount: toAddress(b.graphAccount),
    inputCiphertexts: b.inputCiphertexts.map(toAddress),
    outputCiphertexts: b.outputCiphertexts.map(toAddress),
  });
  const tx = await buildUnsignedTransaction({
    feePayer: payer,
    instructions: [ix],
    computeUnitLimit: 1_400_000,
  });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

const commitBody = z.object({
  authority: z.string(),
  authorityPda: z.string(),
  ciphertextAccount: z.string(),
  digestBase64: Base64String,
});

graphRoutes.post('/commit/prepare', zValidator('json', commitBody), async (c) => {
  const b = c.req.valid('json');
  const digest = decodeBase64(b.digestBase64);
  if (digest.length !== 32) throw Errors.badRequest('digest must be 32 bytes');
  const authority = toAddress(b.authority);
  const ix = buildCommitCiphertextIx({
    authorityPda: toAddress(b.authorityPda),
    signer: authority,
    ciphertextAccount: toAddress(b.ciphertextAccount),
    digest,
  });
  const tx = await buildUnsignedTransaction({
    feePayer: authority,
    instructions: [ix],
  });
  return c.json({ unsignedTx: serializeUnsignedTx(tx) });
});

const submitBody = z.object({
  signedTxBase64: z.string(),
  skipPreflight: z.boolean().optional(),
});

graphRoutes.post('/submit', zValidator('json', submitBody), async (c) => {
  const b = c.req.valid('json');
  const signature = await submitWireTransaction(b.signedTxBase64, b.skipPreflight ?? false);
  return c.json({ signature });
});

graphRoutes.get('/status/:signature', async (c) => {
  const status = await getTransactionStatus(c.req.param('signature'));
  return c.json(status);
});

// --- DSL operation registry ---

graphRoutes.get('/operations', (c) => c.json({ operations: listOperations() }));

const registerOpBody = z.object({
  name: z.string().min(1),
  graphBytesBase64: Base64String,
});

graphRoutes.post('/operations/register-bytes', zValidator('json', registerOpBody), async (c) => {
  const b = c.req.valid('json');
  const existing = getOperation(b.name);
  if (!existing) throw Errors.badRequest(`Unknown operation slot "${b.name}"`);
  const bytes = decodeBase64(b.graphBytesBase64);
  registerOperation(b.name, { ...existing, graphBytes: bytes });
  return c.json({ ok: true, name: b.name, byteLength: bytes.length });
});
