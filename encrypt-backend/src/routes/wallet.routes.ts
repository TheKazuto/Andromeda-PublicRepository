import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { address as toAddress } from '@solana/kit';
import { initEncryptedBalance } from '../wallet/initBalance.js';
import { buildEncryptedTransfer } from '../wallet/transfer.js';
import { buildDeposit, buildWithdraw } from '../wallet/depositWithdraw.js';
import { buildBalanceCheck } from '../wallet/balanceCheck.js';
import { fetchEncodedAccount } from '@solana/kit';
import { rpc } from '../solana/connection.js';
import { accountDataToBase64 } from '../lib/responses.js';

export const walletRoutes = new Hono();

const initBody = z.object({
  payer: z.string(),
  owner: z.string(),
  authorityPda: z.string(),
  networkEncryptionKey: z.string(),
  ciphertextAccount: z.string(),
});

walletRoutes.post('/balance/init', zValidator('json', initBody), async (c) => {
  const b = c.req.valid('json');
  const result = await initEncryptedBalance({
    payer: toAddress(b.payer),
    owner: toAddress(b.owner),
    authorityPda: toAddress(b.authorityPda),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    ciphertextAccount: toAddress(b.ciphertextAccount),
  });
  return c.json(result);
});

const depositBody = z.object({
  payer: z.string(),
  owner: z.string(),
  authorityPda: z.string(),
  networkEncryptionKey: z.string(),
  configAccount: z.string(),
  depositAccount: z.string(),
  balanceCiphertext: z.string(),
  newBalanceOutput: z.string(),
  amountCiphertextAccount: z.string(),
  amount: z.union([z.string(), z.number()]).transform((v) => BigInt(v)),
});

walletRoutes.post('/balance/deposit/prepare', zValidator('json', depositBody), async (c) => {
  const b = c.req.valid('json');
  const result = await buildDeposit({
    payer: toAddress(b.payer),
    owner: toAddress(b.owner),
    authorityPda: toAddress(b.authorityPda),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    balanceCiphertext: b.balanceCiphertext,
    newBalanceOutput: b.newBalanceOutput,
    amountCiphertextAccount: b.amountCiphertextAccount,
    amountPlaintext: b.amount,
  });
  return c.json(result);
});

walletRoutes.post('/balance/withdraw/prepare', zValidator('json', depositBody), async (c) => {
  const b = c.req.valid('json');
  const result = await buildWithdraw({
    payer: toAddress(b.payer),
    owner: toAddress(b.owner),
    authorityPda: toAddress(b.authorityPda),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    balanceCiphertext: b.balanceCiphertext,
    newBalanceOutput: b.newBalanceOutput,
    amountCiphertextAccount: b.amountCiphertextAccount,
    amountPlaintext: b.amount,
  });
  return c.json(result);
});

const transferBody = z.object({
  payer: z.string(),
  sender: z.string(),
  authorityPda: z.string(),
  networkEncryptionKey: z.string(),
  configAccount: z.string(),
  depositAccount: z.string(),
  senderBalanceCiphertext: z.string(),
  receiverBalanceCiphertext: z.string(),
  amount: z.union([z.string(), z.number()]).transform((v) => BigInt(v)),
  amountCiphertextAccount: z.string(),
  newSenderBalanceOutput: z.string(),
  newReceiverBalanceOutput: z.string(),
  graphName: z.string().optional(),
});

walletRoutes.post('/transfer/prepare', zValidator('json', transferBody), async (c) => {
  const b = c.req.valid('json');
  const result = await buildEncryptedTransfer({
    payer: toAddress(b.payer),
    sender: toAddress(b.sender),
    authorityPda: toAddress(b.authorityPda),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    senderBalanceCiphertext: b.senderBalanceCiphertext,
    receiverBalanceCiphertext: b.receiverBalanceCiphertext,
    amountPlaintext: b.amount,
    amountCiphertextAccount: b.amountCiphertextAccount,
    newSenderBalanceOutput: b.newSenderBalanceOutput,
    newReceiverBalanceOutput: b.newReceiverBalanceOutput,
    graphName: b.graphName,
  });
  return c.json(result);
});

const checkBody = z.object({
  payer: z.string(),
  owner: z.string(),
  authorityPda: z.string(),
  networkEncryptionKey: z.string(),
  configAccount: z.string(),
  depositAccount: z.string(),
  balanceCiphertext: z.string(),
  amount: z.union([z.string(), z.number()]).transform((v) => BigInt(v)),
  amountCiphertextAccount: z.string(),
  resultOutput: z.string(),
  graphName: z.enum(['cmp_gt_u64', 'cmp_lt_u64', 'cmp_eq_u64']).optional(),
});

walletRoutes.post('/balance/check/prepare', zValidator('json', checkBody), async (c) => {
  const b = c.req.valid('json');
  const result = await buildBalanceCheck({
    payer: toAddress(b.payer),
    owner: toAddress(b.owner),
    authorityPda: toAddress(b.authorityPda),
    networkEncryptionKey: toAddress(b.networkEncryptionKey),
    configAccount: toAddress(b.configAccount),
    depositAccount: toAddress(b.depositAccount),
    balanceCiphertext: b.balanceCiphertext,
    amountPlaintext: b.amount,
    amountCiphertextAccount: b.amountCiphertextAccount,
    resultOutput: b.resultOutput,
    graphName: b.graphName,
  });
  return c.json(result);
});

walletRoutes.get('/balance/:account', async (c) => {
  const addr = c.req.param('account');
  try {
    const account = await fetchEncodedAccount(rpc, toAddress(addr));
    if (!account.exists) return c.json({ exists: false });
    return c.json({
      exists: true,
      account: addr,
      lamports: account.lamports.toString(),
      owner: String(account.programAddress),
      data: accountDataToBase64(account.data),
    });
  } catch (err) {
    return c.json({ error: String(err) }, 502);
  }
});
