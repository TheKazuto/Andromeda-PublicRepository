import { address, type Address } from '@solana/kit';
import { config } from '../config.js';

export const ENCRYPT_PROGRAM_ID: Address = address(config.ENCRYPT_PROGRAM_ID);

// Solana System Program (used as helper / fee payer creation in some flows)
export const SYSTEM_PROGRAM_ID: Address = address('11111111111111111111111111111111');
