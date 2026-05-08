import { createSolanaRpc, createSolanaRpcSubscriptions } from '@solana/kit';
import { config } from '../config.js';

export const rpc = createSolanaRpc(config.SOLANA_RPC_URL);
export const rpcSubscriptions = createSolanaRpcSubscriptions(config.SOLANA_RPC_WS_URL);

export const commitment = config.SOLANA_COMMITMENT;
