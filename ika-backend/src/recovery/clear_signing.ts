/**
 * Clear-signing renderers — turn the typed parameters of a governance
 * challenge into a deterministic ASCII message that the approver reads
 * before signing, and that the on-chain handler recomputes from the
 * same typed parameters.
 *
 * Mirrors `contracts/auth/src/human_message.rs` byte-for-byte. Any
 * wire-format change must update Rust, this file, the Go mirror
 * (`gateway/internal/auth/clear_signing.go`), and the golden vectors in
 * the same commit.
 *
 * Output is always plain ASCII (`0x20..=0x7E`), valid UTF-8, fits in
 * [`MAX_HUMAN_MESSAGE_BYTES`] = 512.
 */

/**
 * Maximum byte length of a rendered clear-signing message.
 *
 * Mirrors `contracts/auth/src/human_message.rs::MAX_HUMAN_MESSAGE_BYTES`.
 * Originally 512 in the v2 spec; raised to 768 on 2026-05-14 to fit the
 * `quorum-contribute` full-session-snapshot template in the worst case.
 */
export const MAX_HUMAN_MESSAGE_BYTES = 768

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

const MEMBER_SLOT_LEN = 34

export class HumanMessageError extends Error {
  constructor(public readonly kind: 'BufferTooSmall' | 'NonAscii' | 'InvalidSlot') {
    super(`HumanMessageError: ${kind}`)
    this.name = 'HumanMessageError'
  }
}

/**
 * Length of the credential identifier inside a 34-byte member slot for the
 * given scheme tag.
 */
function idLenForScheme(scheme: number): number {
  switch (scheme) {
    case 0:
      return 32 // Ed25519
    case 1:
      return 20 // Secp256k1 (eth address)
    case 2:
      return 33 // Secp256r1 (compressed)
    case 3:
      return 33 // WebAuthn (compressed)
    case 4:
      return 32 // OIDC (addr_seed)
    default:
      throw new HumanMessageError('InvalidSlot')
  }
}

/**
 * ASCII writer with a fixed 512-byte capacity. Mirrors the Rust
 * `MsgWriter` byte-for-byte.
 */
export class MsgWriter {
  private readonly buf = new Uint8Array(MAX_HUMAN_MESSAGE_BYTES)
  private cursor = 0

  get length(): number {
    return this.cursor
  }

  bytes(): Uint8Array {
    return this.buf.subarray(0, this.cursor)
  }

  private pushByte(b: number): void {
    if (this.cursor >= MAX_HUMAN_MESSAGE_BYTES) {
      throw new HumanMessageError('BufferTooSmall')
    }
    this.buf[this.cursor++] = b & 0xff
  }

  private pushBytes(src: Uint8Array): void {
    if (this.cursor + src.length > MAX_HUMAN_MESSAGE_BYTES) {
      throw new HumanMessageError('BufferTooSmall')
    }
    this.buf.set(src, this.cursor)
    this.cursor += src.length
  }

  writeStr(s: string): void {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i)
      if (c < 0x20 || c > 0x7e) {
        throw new HumanMessageError('NonAscii')
      }
    }
    this.pushBytes(asciiBytes(s))
  }

  writeU8Dec(v: number): void {
    this.writeU64Dec(BigInt(v & 0xff))
  }

  writeU16Dec(v: number): void {
    this.writeU64Dec(BigInt(v & 0xffff))
  }

  writeU32Dec(v: number): void {
    this.writeU64Dec(BigInt(v >>> 0))
  }

  writeU64Dec(v: bigint): void {
    if (v === 0n) {
      this.pushByte(0x30) // '0'
      return
    }
    let n = v
    const digits: number[] = []
    while (n > 0n) {
      digits.push(Number(n % 10n))
      n /= 10n
    }
    for (let i = digits.length - 1; i >= 0; i--) {
      this.pushByte(0x30 + (digits[i] as number))
    }
  }

  writeI64Dec(v: bigint): void {
    if (v < 0n) {
      this.pushByte(0x2d) // '-'
      this.writeU64Dec(-v)
    } else {
      this.writeU64Dec(v)
    }
  }

  writeHexLower(bytes: Uint8Array): void {
    if (this.cursor + bytes.length * 2 > MAX_HUMAN_MESSAGE_BYTES) {
      throw new HumanMessageError('BufferTooSmall')
    }
    for (const b of bytes) {
      this.buf[this.cursor++] = HEX_LC[(b >> 4) & 0x0f] as number
      this.buf[this.cursor++] = HEX_LC[b & 0x0f] as number
    }
  }

  writeBase58_32(addr: Uint8Array): void {
    if (addr.length !== 32) {
      throw new HumanMessageError('InvalidSlot')
    }
    this.pushBytes(asciiBytes(encodeBase58_32(addr)))
  }

  writeMemberSlot(slot: Uint8Array): void {
    if (slot.length !== MEMBER_SLOT_LEN) {
      throw new HumanMessageError('InvalidSlot')
    }
    const scheme = slot[0] as number
    const idLen = idLenForScheme(scheme)
    this.writeStr('scheme:')
    this.writeU8Dec(scheme)
    this.writeStr(';id:')
    this.writeHexLower(slot.subarray(1, 1 + idLen))
  }

  writeOptionU64(some: boolean | number, v: bigint): void {
    const isSome = typeof some === 'boolean' ? some : some !== 0
    if (!isSome) {
      this.writeStr('none')
    } else {
      this.writeU64Dec(v)
    }
  }
}

const HEX_LC = new Uint8Array([
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
])

function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff
  return out
}

/**
 * base58 of exactly 32 bytes (Solana address layout). Output 32..44 chars.
 */
function encodeBase58_32(input: Uint8Array): string {
  let leadingZeros = 0
  while (leadingZeros < input.length && input[leadingZeros] === 0) {
    leadingZeros++
  }

  const digits: number[] = []
  for (let i = leadingZeros; i < input.length; i++) {
    let carry = input[i] as number
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }

  let out = ''
  for (let i = 0; i < leadingZeros; i++) out += '1'
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i] as number]
  return out
}

// Public utility: render bytes to base58, used by gateway/audit log when
// presenting addresses in `clearSigning.fields`.
export function base58Encode32(input: Uint8Array): string {
  if (input.length !== 32) throw new HumanMessageError('InvalidSlot')
  return encodeBase58_32(input)
}

function renderToString(fn: (w: MsgWriter) => void): string {
  const w = new MsgWriter()
  fn(w)
  return new TextDecoder('ascii').decode(w.bytes())
}

// ============================================================================
// Phase 1 — rules-policy recovery (3)
// ============================================================================

export function primaryRecoverMessage(input: {
  dwallet: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
}): string {
  return renderToString((w) => {
    w.writeStr('Recover dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' for message ')
    w.writeHexLower(input.messageDigest)
    w.writeStr(' metadata ')
    w.writeHexLower(input.metadataDigest)
    w.writeStr(' scheme ')
    w.writeU16Dec(input.signatureScheme)
    w.writeStr(' user ')
    w.writeHexLower(input.userPubkey)
  })
}

export function quorumSessionOpenMessage(input: {
  dwallet: Uint8Array
  amount: bigint
  destination: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  signatureScheme: number
  expiresAtUnix: bigint
}): string {
  return renderToString((w) => {
    w.writeStr('Open quorum session for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' amount ')
    w.writeU64Dec(input.amount)
    w.writeStr(' destination ')
    w.writeHexLower(input.destination)
    w.writeStr(' message ')
    w.writeHexLower(input.messageDigest)
    w.writeStr(' metadata ')
    w.writeHexLower(input.metadataDigest)
    w.writeStr(' scheme ')
    w.writeU16Dec(input.signatureScheme)
    w.writeStr(' expires ')
    w.writeI64Dec(input.expiresAtUnix)
  })
}

export function quorumContributeMessage(input: {
  session: Uint8Array
  memberSlot: Uint8Array
  dwallet: Uint8Array
  amount: bigint
  destination: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
  expiresAtUnix: bigint
}): string {
  return renderToString((w) => {
    w.writeStr('Contribute to quorum session ')
    w.writeBase58_32(input.session)
    w.writeStr(' as member ')
    w.writeMemberSlot(input.memberSlot)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' amount ')
    w.writeU64Dec(input.amount)
    w.writeStr(' destination ')
    w.writeHexLower(input.destination)
    w.writeStr(' message ')
    w.writeHexLower(input.messageDigest)
    w.writeStr(' metadata ')
    w.writeHexLower(input.metadataDigest)
    w.writeStr(' scheme ')
    w.writeU16Dec(input.signatureScheme)
    w.writeStr(' user ')
    w.writeHexLower(input.userPubkey)
    w.writeStr(' expires ')
    w.writeI64Dec(input.expiresAtUnix)
  })
}

// ============================================================================
// Phase 1 — rules-policy admin (12)
// ============================================================================

export function adminAddMemberMessage(input: {
  newMemberSlot: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Add member ')
    w.writeMemberSlot(input.newMemberSlot)
    w.writeStr(' to policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminRemoveMemberMessage(input: {
  memberSlot: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Remove member ')
    w.writeMemberSlot(input.memberSlot)
    w.writeStr(' from policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminAddDestinationMessage(input: {
  destination: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Allow destination ')
    w.writeHexLower(input.destination)
    w.writeStr(' on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminRemoveDestinationMessage(input: {
  destination: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Block destination ')
    w.writeHexLower(input.destination)
    w.writeStr(' on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminRevokeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Revoke policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminSetPrimaryMessage(input: {
  newPrimarySlot: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Set primary to ')
    w.writeMemberSlot(input.newPrimarySlot)
    w.writeStr(' on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminSetQuorumThresholdImmediateMessage(input: {
  newThreshold: number
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Set quorum threshold to ')
    w.writeU8Dec(input.newThreshold)
    w.writeStr(' immediately on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminSetDailyLimitImmediateMessage(input: {
  newSome: boolean
  newLimit: bigint
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Set daily limit to ')
    w.writeOptionU64(input.newSome, input.newLimit)
    w.writeStr(' immediately on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminSetCooldownImmediateMessage(input: {
  newCooldownSeconds: bigint
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Set cooldown to ')
    w.writeU64Dec(input.newCooldownSeconds)
    w.writeStr(' seconds immediately on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminProposeQuorumThresholdMessage(input: {
  newThreshold: number
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Propose quorum threshold ')
    w.writeU8Dec(input.newThreshold)
    w.writeStr(' on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminProposeDailyLimitMessage(input: {
  newSome: boolean
  newLimit: bigint
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Propose daily limit ')
    w.writeOptionU64(input.newSome, input.newLimit)
    w.writeStr(' on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function adminProposeCooldownMessage(input: {
  newCooldownSeconds: bigint
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Propose cooldown ')
    w.writeU64Dec(input.newCooldownSeconds)
    w.writeStr(' seconds on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// Phase 1 — rules-policy OIDC (2)
// ============================================================================

export function oidcSessionOpenMessage(input: {
  dwallet: Uint8Array
  notAfterUnixTs: bigint
  ephPk: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Open OIDC session for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' until ')
    w.writeU64Dec(input.notAfterUnixTs)
    w.writeStr(' using ephemeral key ')
    w.writeHexLower(input.ephPk)
  })
}

export function oidcPrimaryUseMessage(input: {
  session: Uint8Array
  dwallet: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
}): string {
  return renderToString((w) => {
    w.writeStr('Authorize OIDC session ')
    w.writeBase58_32(input.session)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' message ')
    w.writeHexLower(input.messageDigest)
    w.writeStr(' metadata ')
    w.writeHexLower(input.metadataDigest)
    w.writeStr(' scheme ')
    w.writeU16Dec(input.signatureScheme)
    w.writeStr(' user ')
    w.writeHexLower(input.userPubkey)
  })
}

// Passkey-primary session (D1 Opção A). Same shape as OIDC session messages
// — only the "OIDC" word is swapped for "passkey" so users see what they are
// authorising.
export function passkeySessionOpenMessage(input: {
  dwallet: Uint8Array
  notAfterUnixTs: bigint
  ephPk: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Open passkey session for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' until ')
    w.writeU64Dec(input.notAfterUnixTs)
    w.writeStr(' using ephemeral key ')
    w.writeHexLower(input.ephPk)
  })
}

export function passkeyPrimaryUseMessage(input: {
  session: Uint8Array
  dwallet: Uint8Array
  messageDigest: Uint8Array
  metadataDigest: Uint8Array
  userPubkey: Uint8Array
  signatureScheme: number
}): string {
  return renderToString((w) => {
    w.writeStr('Authorize passkey session ')
    w.writeBase58_32(input.session)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' message ')
    w.writeHexLower(input.messageDigest)
    w.writeStr(' metadata ')
    w.writeHexLower(input.metadataDigest)
    w.writeStr(' scheme ')
    w.writeU16Dec(input.signatureScheme)
    w.writeStr(' user ')
    w.writeHexLower(input.userPubkey)
  })
}

// ============================================================================
// Phase 2 — allowlist-destinations admin (4)
// ============================================================================

export function allowlistAddDestinationMessage(input: {
  destination: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Allow destination ')
    w.writeHexLower(input.destination)
    w.writeStr(' on allowlist policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function allowlistRemoveDestinationMessage(input: {
  destination: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Block destination ')
    w.writeHexLower(input.destination)
    w.writeStr(' on allowlist policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function allowlistPauseMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Pause allowlist policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function allowlistResumeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Resume allowlist policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// Phase 2 — velocity-guard admin (3)
// ============================================================================

export function velocityUpdateWindowMessage(input: {
  maxSigsPerWindow: number
  windowSlots: bigint
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Update velocity window on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' to ')
    w.writeU32Dec(input.maxSigsPerWindow)
    w.writeStr(' signatures per ')
    w.writeU64Dec(input.windowSlots)
    w.writeStr(' slots')
  })
}

export function velocityPauseMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Pause velocity-guard policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function velocityResumeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Resume velocity-guard policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// Phase 2 — time-lock admin (3)
// ============================================================================

export function timeLockModeLabel(mode: number): 'before' | 'after' | 'between' | 'recurring' | 'unknown' {
  switch (mode) {
    case 0:
      return 'before'
    case 1:
      return 'after'
    case 2:
      return 'between'
    case 3:
      return 'recurring'
    default:
      return 'unknown'
  }
}

export function timeLockUpdateWindowMessage(input: {
  mode: number
  startSlot: bigint
  endSlot: bigint
  recurringPeriodSlots: bigint
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Update time-lock window on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' mode ')
    w.writeStr(timeLockModeLabel(input.mode))
    w.writeStr(' start ')
    w.writeU64Dec(input.startSlot)
    w.writeStr(' end ')
    w.writeU64Dec(input.endSlot)
    w.writeStr(' period ')
    w.writeU64Dec(input.recurringPeriodSlots)
  })
}

export function timeLockPauseMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Pause time-lock policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function timeLockResumeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Resume time-lock policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// Phase 2 — oracle-conditional admin (3)
// ============================================================================

export function oracleUpdateBoundsMessage(input: {
  minPrice: bigint
  maxPrice: bigint
  maxAgeSlots: bigint
  maxConfidenceBps: number
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Update oracle bounds on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' min ')
    w.writeI64Dec(input.minPrice)
    w.writeStr(' max ')
    w.writeI64Dec(input.maxPrice)
    w.writeStr(' maxAge ')
    w.writeU64Dec(input.maxAgeSlots)
    w.writeStr(' maxConfidence ')
    w.writeU16Dec(input.maxConfidenceBps)
    w.writeStr(' bps')
  })
}

export function oraclePauseMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Pause oracle-conditional policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function oracleResumeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Resume oracle-conditional policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// Phase 2 — passkey-step-up admin (3)
// ============================================================================

export function passkeyUpdatePolicyMessage(input: {
  thresholdAmount: bigint
  passkeyPubkey: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Update passkey step-up on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' threshold ')
    w.writeU64Dec(input.thresholdAmount)
    w.writeStr(' passkey ')
    w.writeHexLower(input.passkeyPubkey)
  })
}

export function passkeyPauseMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Pause passkey step-up policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function passkeyResumeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Resume passkey step-up policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// Phase 2 — session-keys admin (4)
// ============================================================================

export function sessionKeysRevokeSessionMessage(input: {
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Revoke session keys on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function sessionKeysAddAllowedProgramMessage(input: {
  programId: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Allow program ')
    w.writeBase58_32(input.programId)
    w.writeStr(' on session-keys policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function sessionKeysRemoveAllowedProgramMessage(input: {
  programId: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Block program ')
    w.writeBase58_32(input.programId)
    w.writeStr(' on session-keys policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function sessionKeysCloseSessionMessage(input: {
  recipient: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Close session-keys policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' refund recipient ')
    w.writeBase58_32(input.recipient)
  })
}

// ============================================================================
// Phase 2 — fhe-gated admin (3)
// ============================================================================

export function fheRotateAuthorityMessage(input: {
  newFheAuthority: Uint8Array
  policy: Uint8Array
  dwallet: Uint8Array
}): string {
  return renderToString((w) => {
    w.writeStr('Rotate FHE authority on policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
    w.writeStr(' to ')
    w.writeBase58_32(input.newFheAuthority)
  })
}

export function fhePauseMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Pause fhe-gated policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

export function fheResumeMessage(input: { policy: Uint8Array; dwallet: Uint8Array }): string {
  return renderToString((w) => {
    w.writeStr('Resume fhe-gated policy ')
    w.writeBase58_32(input.policy)
    w.writeStr(' for dWallet ')
    w.writeBase58_32(input.dwallet)
  })
}

// ============================================================================
// ClearSigning envelope
// ============================================================================

export interface ClearSigning {
  version: string
  operation: string
  fields: Record<string, string | number | boolean>
}

export const CLEAR_SIGNING_VERSION_RULES_POLICY = 'rules-policy-clear-v1'
export const CLEAR_SIGNING_VERSION_POLICY = 'policy-clear-v1'
