import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import { getOperation } from '../dsl/operations.js';
import { buildExecuteGraphIx } from '../graph/builder.js';
import { buildUnsignedTransaction } from '../solana/instructions.js';
import { Errors } from '../lib/errors.js';
import { FHE_TYPE_NAME, FheType } from '../dsl/types.js';
import { serializeUnsignedTx } from '../lib/responses.js';

export const dslRoutes = new Hono();

dslRoutes.get('/types', (c) =>
  c.json({
    types: Object.entries(FheType).map(([name, id]) => ({ name, id })),
  })
);

const opBody = z.object({
  name: z.string(),
  payer: z.string(),
  signer: z.string(),
  configAccount: z.string(),
  depositAccount: z.string(),
  networkEncryptionKey: z.string(),
  inputCiphertexts: z.array(z.string()).min(1),
  outputCiphertexts: z.array(z.string()).min(1),
});

/**
 * Generic DSL op endpoint — looks up the registered graph by name and builds
 * the corresponding execute_graph instruction. Same semantics as
 * /v1/graph/execute/prepare but lets clients refer to operations by friendly
 * name ("add_u64", "cmp_gt_u64", etc.).
 */
dslRoutes.post('/op/prepare', zValidator('json', opBody), async (c) => {
  const b = c.req.valid('json');
  const op = getOperation(b.name);
  if (!op) throw Errors.notFound(`Operation "${b.name}" not found`);
  if (op.graphBytes.length === 0) {
    throw Errors.graph(`Operation "${b.name}" has no graph bytes registered yet`);
  }

  const payer = toAddress(b.payer);
  const ix = buildExecuteGraphIx({
    payer,
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    caller: toAddress(b.signer),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    graphBytes: op.graphBytes,
    inputCiphertexts: b.inputCiphertexts.map(toAddress),
    outputCiphertexts: b.outputCiphertexts.map(toAddress),
  });

  const tx = await buildUnsignedTransaction({
    feePayer: payer,
    instructions: [ix],
    computeUnitLimit: 1_400_000,
  });

  return c.json({
    operation: {
      name: b.name,
      kind: op.kind,
      inputTypes: op.inputTypes.map((id) => FHE_TYPE_NAME[id] ?? id),
      outputTypes: op.outputTypes.map((id) => FHE_TYPE_NAME[id] ?? id),
    },
    unsignedTx: serializeUnsignedTx(tx),
  });
});
