// Sui Move transaction decoder (advisory).
//
// Sui's `TransactionData` is BCS-encoded. We decode just enough of the V1
// ProgrammableTransaction tree to surface, for the advisory risk layer:
//   - the sender (cross-checked against the dWallet at the intents-backend),
//   - the count and shape of commands (MoveCall / TransferObjects /
//     SplitCoins / MergeCoins / Publish / Upgrade),
//   - the fully-qualified id of every MoveCall (`pkg::module::function`),
//   - a `none` level when every MoveCall is a built-in `0x2::pay::*` /
//     `0x2::transfer::*` transfer (no special risk),
//   - a `high` level when Publish / Upgrade appears (package mutation),
//   - a `medium` level for any unknown MoveCall (third-party Move logic the
//     decoder cannot verify the effects of — DEX swap, lending, NFT mint, …).
//
// Out of scope for now (extending the decoder is incremental):
//   - resolving Argument references back to their Pure inputs to extract
//     recipient addresses + amounts (TransferObjects' recipient is an
//     Argument, not the address bytes themselves);
//   - rendering TypeTag generics in pretty form (`Coin<0xa1::usdc::USDC>`);
//   - whitelisting known DEX/lending packages (Cetus, Turbos, Aftermath, …)
//     to lower a known protocol to `low`.
//
// The Move-call decoder mirrors the pattern in `aptos.ts` (Aptos also uses
// BCS); the BCS reader is the shared `ByteReader`. Failures are caught and
// returned as `unverifiable()` so the caller degrades honestly.

import type { CalldataRisk } from '../types.js'
import { ByteReader } from './bytereader.js'
import {
  hexToBytes,
  messageSignature,
  unverifiable,
  type ChainDecoder,
} from './registry.js'

// Built-in coin movement functions — calling these is "moving the user's own
// coins" with no special risk surface. The address `0x2` is the Sui framework
// package (well-known). Mirrors `TRANSFER_FUNCTIONS` in `aptos.ts:21-26`.
const TRANSFER_FUNCTIONS = new Set<string>([
  '0x2::pay::split_and_transfer',
  '0x2::pay::split_vec',
  '0x2::pay::split',
  '0x2::pay::divide_and_keep',
  '0x2::pay::join',
  '0x2::pay::join_vec',
  '0x2::pay::keep',
  '0x2::transfer::public_transfer',
  '0x2::transfer::transfer',
  '0x2::transfer::public_share_object',
])

/** Decoded view of a programmable Move call (one Command of kind MoveCall). */
interface MoveCallView {
  kind: 'MoveCall'
  /** Fully-qualified id: `pkg::module::function`. Address is short-form. */
  fqid: string
  /** Number of type arguments (rendered count only — strings skipped). */
  nTypeArgs: number
  /** Number of regular arguments. */
  nArgs: number
}

/** Decoded view of one programmable command. */
type Command =
  | MoveCallView
  | { kind: 'TransferObjects'; nObjects: number }
  | { kind: 'SplitCoins'; nAmounts: number }
  | { kind: 'MergeCoins'; nSources: number }
  | { kind: 'MakeMoveVec' }
  | { kind: 'Publish' }
  | { kind: 'Upgrade' }

/** Decoded view of the whole TransactionData::V1. */
interface DecodedTx {
  sender: string
  inputs: { pure: number; object: number }
  commands: Command[]
}

// ── BCS primitive readers ───────────────────────────────────────────────────

/** Strip leading zero bytes (canonical short-form Sui address). */
function shortAddress(hex32: string): string {
  const stripped = hex32.replace(/^0+/, '')
  return `0x${stripped || '0'}`
}

/** ObjectRef = (ObjectID:32, SequenceNumber:u64, ObjectDigest:32). */
function readObjectRef(r: ByteReader): void {
  r.fixed(32)
  r.u64le()
  r.fixed(32)
}

/**
 * Argument = enum { GasCoin=0, Input(u16)=1, Result(u16)=2, NestedResult(u16,u16)=3 }.
 * u16 is encoded as 2 LE bytes in BCS.
 */
function readArgument(r: ByteReader): void {
  const tag = r.uleb()
  switch (tag) {
    case 0:
      return
    case 1:
    case 2:
      r.fixed(2)
      return
    case 3:
      r.fixed(4)
      return
    default:
      throw new Error(`unknown Argument variant ${tag}`)
  }
}

/**
 * TypeTag = enum { Bool=0, U8=1, U64=2, U128=3, Address=4, Signer=5,
 * Vector(TypeTag)=6, Struct(StructTag)=7, U16=8, U32=9, U256=10 }.
 * We skip past the bytes (no string render for the MVP).
 */
function skipTypeTag(r: ByteReader): void {
  const tag = r.uleb()
  switch (tag) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 8:
    case 9:
    case 10:
      return
    case 6:
      skipTypeTag(r)
      return
    case 7: {
      // StructTag { address(32), module, name, type_args: Vec<TypeTag> }
      r.fixed(32)
      r.bcsString()
      r.bcsString()
      const n = r.uleb()
      for (let i = 0; i < n; i += 1) skipTypeTag(r)
      return
    }
    default:
      throw new Error(`unknown TypeTag variant ${tag}`)
  }
}

/**
 * CallArg = enum { Pure(Vec<u8>)=0, Object(ObjectArg)=1 }. ObjectArg has its
 * own variants (ImmOrOwnedObject, SharedObject, Receiving). Returns the
 * coarse category for input counting; the bytes are skipped.
 */
function readCallArg(r: ByteReader): 'pure' | 'object' {
  const tag = r.uleb()
  switch (tag) {
    case 0: {
      const n = r.uleb()
      r.fixed(n)
      return 'pure'
    }
    case 1: {
      const inner = r.uleb()
      switch (inner) {
        case 0: // ImmOrOwnedObject(ObjectRef)
        case 2: // Receiving(ObjectRef)
          readObjectRef(r)
          return 'object'
        case 1: // SharedObject { id, initial_shared_version, mutable: bool }
          r.fixed(32)
          r.u64le()
          r.u8()
          return 'object'
        default:
          throw new Error(`unknown ObjectArg variant ${inner}`)
      }
    }
    default:
      throw new Error(`unknown CallArg variant ${tag}`)
  }
}

/**
 * Command = enum {
 *   MoveCall(ProgrammableMoveCall)=0,
 *   TransferObjects(Vec<Argument>, Argument)=1,
 *   SplitCoins(Argument, Vec<Argument>)=2,
 *   MergeCoins(Argument, Vec<Argument>)=3,
 *   Publish(Vec<Vec<u8>>, Vec<ObjectID>)=4,
 *   MakeMoveVec(Option<TypeTag>, Vec<Argument>)=5,
 *   Upgrade(Vec<Vec<u8>>, Vec<ObjectID>, ObjectID, Argument)=6,
 * }
 */
function readCommand(r: ByteReader): Command {
  const tag = r.uleb()
  switch (tag) {
    case 0: {
      // ProgrammableMoveCall { package(32), module, function, ty_args, args }
      const pkg = shortAddress(r.hex(32))
      const mod = r.bcsString()
      const fn = r.bcsString()
      const nTypeArgs = r.uleb()
      for (let i = 0; i < nTypeArgs; i += 1) skipTypeTag(r)
      const nArgs = r.uleb()
      for (let i = 0; i < nArgs; i += 1) readArgument(r)
      return { kind: 'MoveCall', fqid: `${pkg}::${mod}::${fn}`, nTypeArgs, nArgs }
    }
    case 1: {
      const n = r.uleb()
      for (let i = 0; i < n; i += 1) readArgument(r)
      readArgument(r) // recipient
      return { kind: 'TransferObjects', nObjects: n }
    }
    case 2: {
      readArgument(r) // source coin
      const n = r.uleb()
      for (let i = 0; i < n; i += 1) readArgument(r)
      return { kind: 'SplitCoins', nAmounts: n }
    }
    case 3: {
      readArgument(r) // destination coin
      const n = r.uleb()
      for (let i = 0; i < n; i += 1) readArgument(r)
      return { kind: 'MergeCoins', nSources: n }
    }
    case 4: {
      // Publish(Vec<Vec<u8>> modules, Vec<ObjectID> deps)
      const nMods = r.uleb()
      for (let i = 0; i < nMods; i += 1) {
        const len = r.uleb()
        r.fixed(len)
      }
      const nDeps = r.uleb()
      for (let i = 0; i < nDeps; i += 1) r.fixed(32)
      return { kind: 'Publish' }
    }
    case 5: {
      // MakeMoveVec(Option<TypeTag>, Vec<Argument>)
      const has = r.u8()
      if (has === 1) skipTypeTag(r)
      const n = r.uleb()
      for (let i = 0; i < n; i += 1) readArgument(r)
      return { kind: 'MakeMoveVec' }
    }
    case 6: {
      // Upgrade(Vec<Vec<u8>>, Vec<ObjectID>, ObjectID, Argument)
      const nMods = r.uleb()
      for (let i = 0; i < nMods; i += 1) {
        const len = r.uleb()
        r.fixed(len)
      }
      const nDeps = r.uleb()
      for (let i = 0; i < nDeps; i += 1) r.fixed(32)
      r.fixed(32) // package being upgraded
      readArgument(r) // UpgradeTicket
      return { kind: 'Upgrade' }
    }
    default:
      throw new Error(`unknown Command variant ${tag}`)
  }
}

function readProgrammableTransaction(r: ByteReader): {
  inputs: { pure: number; object: number }
  commands: Command[]
} {
  const inputCount = r.uleb()
  let pure = 0
  let object = 0
  for (let i = 0; i < inputCount; i += 1) {
    const kind = readCallArg(r)
    if (kind === 'pure') pure += 1
    else object += 1
  }
  const commandCount = r.uleb()
  const commands: Command[] = []
  for (let i = 0; i < commandCount; i += 1) commands.push(readCommand(r))
  return { inputs: { pure, object }, commands }
}

/**
 * Decode `TransactionData::V1(ProgrammableTransaction)` enough to surface the
 * sender, the input shape, and every Command. GasData + Expiration come
 * AFTER sender in the layout — they are not read because the advisory does
 * not need them, and stopping early on a truncated payload keeps the decoder
 * resilient to BCS version drift.
 */
function decodeTransactionData(payloadHex: string): DecodedTx {
  const r = new ByteReader(hexToBytes(payloadHex))
  const version = r.uleb()
  if (version !== 0) throw new Error(`unsupported TransactionData version ${version}`)
  const kindTag = r.uleb()
  if (kindTag !== 0) throw new Error(`unsupported TransactionKind ${kindTag} (only ProgrammableTransaction is decoded)`)
  const pt = readProgrammableTransaction(r)
  if (r.remaining < 32) throw new Error('payload truncated before sender')
  const sender = shortAddress(r.hex(32))
  return { sender, ...pt }
}

// ── Risk synthesis ──────────────────────────────────────────────────────────

function decodeSui(payloadHex: string): CalldataRisk {
  let decoded: DecodedTx
  try {
    decoded = decodeTransactionData(payloadHex)
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'unknown'
    return unverifiable(`failed to decode Sui transaction (${msg}); effects cannot be verified`)
  }

  const moveCalls = decoded.commands.filter(
    (c): c is MoveCallView => c.kind === 'MoveCall',
  )
  const transferObjs = decoded.commands.filter((c) => c.kind === 'TransferObjects')
  const splitCoins = decoded.commands.filter((c) => c.kind === 'SplitCoins')
  const mergeCoins = decoded.commands.filter((c) => c.kind === 'MergeCoins')
  const hasPublish = decoded.commands.some((c) => c.kind === 'Publish')
  const hasUpgrade = decoded.commands.some((c) => c.kind === 'Upgrade')

  const reasons: string[] = [
    `Sui programmable tx · sender ${decoded.sender} · ${decoded.commands.length} command(s), ${decoded.inputs.pure} pure / ${decoded.inputs.object} object input(s)`,
  ]

  if (moveCalls.length > 0) {
    const uniqueFns = [...new Set(moveCalls.map((c) => c.fqid))]
    const shown = uniqueFns.slice(0, 4).join(', ')
    const more = uniqueFns.length > 4 ? `, …+${uniqueFns.length - 4}` : ''
    reasons.push(`Move calls: ${shown}${more}`)
  }
  if (transferObjs.length > 0) {
    const total = transferObjs.reduce((acc, c) => acc + c.nObjects, 0)
    reasons.push(`${transferObjs.length} TransferObjects (${total} object(s))`)
  }
  if (splitCoins.length > 0) reasons.push(`${splitCoins.length} SplitCoins`)
  if (mergeCoins.length > 0) reasons.push(`${mergeCoins.length} MergeCoins`)

  // Publish / Upgrade mutate Move packages — always high-risk for the user.
  if (hasPublish || hasUpgrade) {
    reasons.push(hasPublish ? 'package Publish present' : 'package Upgrade present')
    return { level: 'high', reasons, effectsExtracted: true }
  }

  // No MoveCall + at least one TransferObjects = a coin split-and-transfer
  // built without a Move-level helper (Sui SDKs emit this for plain transfers).
  if (moveCalls.length === 0 && transferObjs.length > 0) {
    return { level: 'none', reasons, effectsExtracted: true }
  }

  // Every MoveCall is a known built-in transfer/pay helper — no special risk.
  if (moveCalls.length > 0 && moveCalls.every((c) => TRANSFER_FUNCTIONS.has(c.fqid))) {
    return { level: 'none', reasons, effectsExtracted: true }
  }

  // Empty tx (no commands at all) — odd, but advisory-only: flag medium.
  if (decoded.commands.length === 0) {
    reasons.push('transaction has zero commands')
    return { level: 'medium', reasons, effectsExtracted: true }
  }

  // Some MoveCall to a non-builtin package. The decoder cannot verify the
  // effects of arbitrary Move logic (DEX swap, lending, NFT mint, …), so
  // surface this honestly: medium, with the package id visible in `reasons`.
  return {
    level: 'medium',
    reasons: [...reasons, 'one or more Move calls go to non-builtin packages; verify the targets'],
    effectsExtracted: true,
  }
}

export const suiDecoder: ChainDecoder = {
  family: 'Sui',
  decode: (payloadHex, kind) => (kind === 'message' ? messageSignature() : decodeSui(payloadHex)),
}
