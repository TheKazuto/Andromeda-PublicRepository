/**
 * High-level DSL operation descriptors.
 *
 * In Encrypt, complex computations are expressed as graphs (DAGs of FHE ops)
 * via `#[encrypt_fn]` / `#[encrypt_fn_graph]` macros at compile time. Off-chain
 * callers cannot author new graphs at runtime — they must reference
 * pre-compiled graph bytecode.
 *
 * This module provides a registry of common pre-compiled operations the
 * encrypt-backend exposes via REST. Each operation maps a logical name to:
 *   - the operation kind (add / sub / mul / cmp / select / vector / bitwise)
 *   - the expected input / output FHE types
 *   - the graph bytes to feed into execute_graph
 *
 * In pre-alpha, the upstream repo ships sample graph bytecode under
 * `chains/solana/examples/`. Operators of this backend are expected to
 * pre-register the graphs they want to expose by calling
 * `registerGraphBytes()` at boot, or by uploading them through
 * `/v1/graph/register-bytes` (admin-only).
 */

import { FheType } from './types.js';

export type OperationKind =
  | 'add'
  | 'sub'
  | 'mul'
  | 'cmp_lt'
  | 'cmp_gt'
  | 'cmp_eq'
  | 'select'
  | 'vector_sum'
  | 'vector_dot'
  | 'vector_gather'
  | 'bit_and'
  | 'bit_or'
  | 'bit_xor';

export type OperationDescriptor = {
  kind: OperationKind;
  inputTypes: number[];
  outputTypes: number[];
  graphBytes: Uint8Array;
  description: string;
};

const registry = new Map<string, OperationDescriptor>();

export function registerOperation(name: string, desc: OperationDescriptor): void {
  registry.set(name, desc);
}

export function getOperation(name: string): OperationDescriptor | undefined {
  return registry.get(name);
}

export function listOperations(): { name: string; kind: OperationKind; description: string }[] {
  return Array.from(registry.entries()).map(([name, d]) => ({
    name,
    kind: d.kind,
    description: d.description,
  }));
}

/**
 * Default operation slots. Graph bytes start empty and must be filled by the
 * operator with the corresponding compiled bytecode. Until that is done, the
 * route layer returns a clear "operation graph not registered" error.
 */
export const DEFAULT_OPERATIONS: Record<string, Omit<OperationDescriptor, 'graphBytes'>> = {
  add_u64: {
    kind: 'add',
    inputTypes: [FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EUint64],
    description: 'Encrypted addition of two EUint64 ciphertexts',
  },
  sub_u64: {
    kind: 'sub',
    inputTypes: [FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EUint64],
    description: 'Encrypted subtraction of two EUint64 ciphertexts',
  },
  mul_u64: {
    kind: 'mul',
    inputTypes: [FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EUint64],
    description: 'Encrypted multiplication of two EUint64 ciphertexts',
  },
  cmp_lt_u64: {
    kind: 'cmp_lt',
    inputTypes: [FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EBool],
    description: 'Encrypted less-than comparison of two EUint64',
  },
  cmp_gt_u64: {
    kind: 'cmp_gt',
    inputTypes: [FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EBool],
    description: 'Encrypted greater-than comparison of two EUint64',
  },
  cmp_eq_u64: {
    kind: 'cmp_eq',
    inputTypes: [FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EBool],
    description: 'Encrypted equality comparison of two EUint64',
  },
  select_u64: {
    kind: 'select',
    inputTypes: [FheType.EBool, FheType.EUint64, FheType.EUint64],
    outputTypes: [FheType.EUint64],
    description: 'Encrypted conditional select: cond ? a : b',
  },
  vector_sum_u64: {
    kind: 'vector_sum',
    inputTypes: [FheType.EUint64Vector],
    outputTypes: [FheType.EUint64],
    description: 'Sum all elements of an encrypted vector',
  },
  vector_dot_u64: {
    kind: 'vector_dot',
    inputTypes: [FheType.EUint64Vector, FheType.EUint64Vector],
    outputTypes: [FheType.EUint64],
    description: 'Dot product of two encrypted vectors',
  },
  bit_and_64: {
    kind: 'bit_and',
    inputTypes: [FheType.EBitVector64, FheType.EBitVector64],
    outputTypes: [FheType.EBitVector64],
    description: 'Bitwise AND of two encrypted bit vectors',
  },
  bit_or_64: {
    kind: 'bit_or',
    inputTypes: [FheType.EBitVector64, FheType.EBitVector64],
    outputTypes: [FheType.EBitVector64],
    description: 'Bitwise OR of two encrypted bit vectors',
  },
  bit_xor_64: {
    kind: 'bit_xor',
    inputTypes: [FheType.EBitVector64, FheType.EBitVector64],
    outputTypes: [FheType.EBitVector64],
    description: 'Bitwise XOR of two encrypted bit vectors',
  },
};

/**
 * Initialize the registry with all default ops, but with empty graph bytes.
 * Operators must call registerOperation(name, { ..., graphBytes }) at boot
 * to enable each op.
 */
export function initOperationRegistry(): void {
  for (const [name, base] of Object.entries(DEFAULT_OPERATIONS)) {
    registry.set(name, { ...base, graphBytes: new Uint8Array(0) });
  }
}
