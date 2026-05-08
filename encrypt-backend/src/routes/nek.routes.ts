import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { getCurrentNek, setNekOverride, NekImmutableError } from '../encrypt/nek.js';
import { decodeBase64 } from '../lib/validation.js';
import { authorizedFromAddress, authorizedFromBytes } from '../encrypt/authorized.js';
import { encodeBase64 } from '../lib/validation.js';

export const nekRoutes = new Hono();

nekRoutes.get('/current', async (c) => {
  const nek = await getCurrentNek();
  return c.json({
    publicKey: nek.publicKeyBase64,
    fetchedAt: nek.fetchedAt,
    source: nek.source,
  });
});

const overrideBody = z.object({
  publicKeyBase64: z.string().nullable(),
});

nekRoutes.post('/override', zValidator('json', overrideBody), async (c) => {
  const b = c.req.valid('json');
  try {
    if (b.publicKeyBase64 === null) {
      setNekOverride(null);
      return c.json({ ok: true, override: false });
    }
    const bytes = decodeBase64(b.publicKeyBase64);
    if (bytes.length !== 32) {
      return c.json({ error: 'NEK public key must be 32 bytes' }, 400);
    }
    setNekOverride(bytes);
    return c.json({ ok: true, override: true });
  } catch (err) {
    if (err instanceof NekImmutableError) {
      return c.json({ error: err.message, code: 'nek_locked' }, 409);
    }
    throw err;
  }
});

const authorizeBody = z.object({
  address: z.string().optional(),
  bytesBase64: z.string().optional(),
});

nekRoutes.post('/authorize', zValidator('json', authorizeBody), async (c) => {
  const b = c.req.valid('json');
  let bytes: Uint8Array;
  if (b.bytesBase64) bytes = authorizedFromBytes(decodeBase64(b.bytesBase64));
  else if (b.address) bytes = authorizedFromAddress(b.address);
  else return c.json({ error: 'Provide either address or bytesBase64' }, 400);
  return c.json({ authorized: encodeBase64(bytes) });
});
