import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { createHash } from 'node:crypto';
import { createInputCiphertexts } from '../encrypt/createInput.js';
import { readCiphertext } from '../encrypt/readCiphertext.js';
import {
  Base64String,
  PubkeyBase58,
  decodeBase64,
  decodeBase64Sized,
  FheTypeId,
} from '../lib/validation.js';
import { fetchEncodedAccount, type Address, address as toAddress } from '@solana/kit';
import { rpc } from '../solana/connection.js';
import { accountDataToBase64 } from '../lib/responses.js';

export const ciphertextRoutes = new Hono();

const createInputBody = z.object({
  inputs: z
    .array(
      z.object({
        ciphertextBytesBase64: Base64String,
        fheType: FheTypeId,
      })
    )
    .min(1)
    .max(64),
  authorizedAddress: PubkeyBase58.optional(),
  authorizedBytesBase64: Base64String.optional(),
  proofBase64: Base64String.optional(),
});

ciphertextRoutes.post('/create', zValidator('json', createInputBody), async (c) => {
  const body = c.req.valid('json');
  const result = await createInputCiphertexts({
    inputs: body.inputs.map((i) => ({
      ciphertextBytes: decodeBase64(i.ciphertextBytesBase64),
      fheType: i.fheType,
    })),
    authorizedAddress: body.authorizedAddress,
    authorizedBytes: body.authorizedBytesBase64
      ? decodeBase64Sized(body.authorizedBytesBase64, 32, 'authorizedBytesBase64')
      : undefined,
    proof: body.proofBase64 ? decodeBase64(body.proofBase64) : undefined,
  });
  return c.json(result);
});

const readBody = z.object({
  messageBase64: Base64String,
  signatureBase64: Base64String,
  signerBase64: Base64String,
});

ciphertextRoutes.post('/read', zValidator('json', readBody), async (c) => {
  const body = c.req.valid('json');
  const message = decodeBase64(body.messageBase64);
  const signature = decodeBase64Sized(body.signatureBase64, 64, 'signatureBase64');
  const signer = decodeBase64Sized(body.signerBase64, 32, 'signerBase64');
  const cacheKey = createHash('sha256')
    .update(message)
    .update(signature)
    .update(signer)
    .digest('hex');
  const result = await readCiphertext({
    message,
    signature,
    signer,
    cacheKey,
  });
  return c.json(result);
});

ciphertextRoutes.get('/account/:address', async (c) => {
  const addr = c.req.param('address');
  try {
    const account = await fetchEncodedAccount(rpc, toAddress(addr) as Address);
    if (!account.exists) return c.json({ exists: false });
    return c.json({
      exists: true,
      lamports: account.lamports.toString(),
      owner: String(account.programAddress),
      data: accountDataToBase64(account.data),
    });
  } catch (err) {
    return c.json({ error: String(err) }, 502);
  }
});
