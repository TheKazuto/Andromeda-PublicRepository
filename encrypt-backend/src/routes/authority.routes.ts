/**
 * Routes wrapping the Authority group (disc 19..21):
 *   - add_authority
 *   - remove_authority
 *   - register_network_encryption_key
 *
 * Operator-only — the upstream API gateway is expected to gate access.
 */

import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import {
  buildAddAuthorityIx,
  buildRemoveAuthorityIx,
  buildRegisterNetworkEncryptionKeyIx,
} from '../graph/authority.js';
import { buildUnsignedTransaction } from '../solana/instructions.js';
import { deriveAuthorityPda, deriveNetworkEncryptionKeyPda } from '../graph/ciphertextAccounts.js';
import { decodeBase64 } from '../lib/validation.js';
import { serializeUnsignedTx } from '../lib/responses.js';

export const authorityRoutes = new Hono();

const addBody = z.object({
  admin: z.string(),
  newAuthority: z.string(),
});

authorityRoutes.post('/add/prepare', zValidator('json', addBody), async (c) => {
  const b = c.req.valid('json');
  const admin = toAddress(b.admin);
  const newAuthority = toAddress(b.newAuthority);
  const [authorityPda] = await deriveAuthorityPda(newAuthority);
  const ix = buildAddAuthorityIx({ admin, newAuthority, authorityPda });
  const tx = await buildUnsignedTransaction({ feePayer: admin, instructions: [ix] });
  return c.json({
    authorityPda: String(authorityPda),
    unsignedTx: serializeUnsignedTx(tx),
  });
});

const removeBody = z.object({
  admin: z.string(),
  authority: z.string(),
});

authorityRoutes.post('/remove/prepare', zValidator('json', removeBody), async (c) => {
  const b = c.req.valid('json');
  const admin = toAddress(b.admin);
  const [authorityPda] = await deriveAuthorityPda(toAddress(b.authority));
  const ix = buildRemoveAuthorityIx({ admin, authorityPda });
  const tx = await buildUnsignedTransaction({ feePayer: admin, instructions: [ix] });
  return c.json({
    authorityPda: String(authorityPda),
    unsignedTx: serializeUnsignedTx(tx),
  });
});

const registerNekBody = z.object({
  payer: z.string(),
  authority: z.string(),
  publicKeyBase64: z.string(),
});

authorityRoutes.post('/register-nek/prepare', zValidator('json', registerNekBody), async (c) => {
  const b = c.req.valid('json');
  const publicKey = decodeBase64(b.publicKeyBase64);
  if (publicKey.length !== 32) {
    return c.json({ error: 'NEK public key must be 32 bytes' }, 400);
  }
  const payer = toAddress(b.payer);
  const [nekPda] = await deriveNetworkEncryptionKeyPda(publicKey);
  const ix = buildRegisterNetworkEncryptionKeyIx({
    payer,
    authority: toAddress(b.authority),
    nekPda,
    publicKey,
  });
  const tx = await buildUnsignedTransaction({ feePayer: payer, instructions: [ix] });
  return c.json({
    nekPda: String(nekPda),
    unsignedTx: serializeUnsignedTx(tx),
  });
});
