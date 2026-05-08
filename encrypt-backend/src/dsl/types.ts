/**
 * Encrypt DSL type identifiers (FHE types).
 *
 * These ids are passed as `fhe_type` in CreateInput / create_*_ciphertext
 * instructions. The Encrypt server validates them in the 0..44 range.
 *
 * Mapping is mirrored from the upstream `encrypt-types` crate. Keep in sync
 * with the developer guide DSL reference if upstream renumbers anything.
 */

export const FheType = {
  EBool: 0,
  EUint8: 1,
  EUint16: 2,
  EUint32: 3,
  EUint64: 4,
  EUint128: 5,
  EUint256: 6,
  EAddress: 7,
  EUint512: 8,
  EUint1024: 9,

  PBool: 128,
  PUint8: 129,
  PUint16: 130,
  PUint32: 131,
  PUint64: 132,
  PUint128: 133,
  PUint256: 134,
  PAddress: 135,

  EBitVector64: 192,
  EUint64Vector: 224,
} as const;

export type FheTypeName = keyof typeof FheType;
export type FheTypeId = (typeof FheType)[FheTypeName];

export const FHE_TYPE_NAME: Record<number, string> = Object.fromEntries(
  Object.entries(FheType).map(([k, v]) => [v, k])
);

/**
 * Returns the byte width of a plaintext value for a given FHE type. Used to
 * validate plaintext payloads sent to create_plaintext_ciphertext.
 */
export function plaintextByteSize(typeId: number): number {
  switch (typeId) {
    case FheType.PUint8:
    case FheType.EUint8:
    case FheType.PBool:
    case FheType.EBool:
      return 1;
    case FheType.PUint16:
    case FheType.EUint16:
      return 2;
    case FheType.PUint32:
    case FheType.EUint32:
      return 4;
    case FheType.PUint64:
    case FheType.EUint64:
    case FheType.EBitVector64:
      return 8;
    case FheType.PUint128:
    case FheType.EUint128:
      return 16;
    default:
      // Vector types — caller determines size
      return 0;
  }
}
