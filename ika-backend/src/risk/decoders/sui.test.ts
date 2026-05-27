import { describe, it, expect } from 'vitest'
import { suiDecoder } from './sui.js'

const ctx = { chainId: 'sui:mainnet', namespace: 'sui', reference: 'mainnet' }

// ── BCS encoders (mirror aptos.test.ts; Sui uses the same BCS format) ──────

function uleb(n: number): number[] {
  const out: number[] = []
  let v = n
  while (v > 0x7f) {
    out.push((v & 0x7f) | 0x80)
    v >>>= 7
  }
  out.push(v)
  return out
}

function u16le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff]
}

function u64le(n: bigint): number[] {
  const out: number[] = []
  let v = n
  for (let i = 0; i < 8; i += 1) {
    out.push(Number(v & 0xffn))
    v >>= 8n
  }
  return out
}

function bcsStr(s: string): number[] {
  const b = [...new TextEncoder().encode(s)]
  return [...uleb(b.length), ...b]
}

function address(hexNoPrefix: string): number[] {
  return [...Buffer.from(hexNoPrefix.padStart(64, '0'), 'hex')]
}

// ── Sui structure builders ──────────────────────────────────────────────────

const SENDER = address('a1b2c3') // dWallet sender address (short form 0xa1b2c3)

/** Argument::Input(idx). u16 LE = 2 bytes. */
function inputArg(idx: number): number[] {
  return [...uleb(1), ...u16le(idx)]
}
/** Argument::Result(idx). */
function resultArg(idx: number): number[] {
  return [...uleb(2), ...u16le(idx)]
}
/** Argument::GasCoin. */
function gasCoin(): number[] {
  return [...uleb(0)]
}
/** Argument::NestedResult(cmd, sub). */
function nestedResult(cmd: number, sub: number): number[] {
  return [...uleb(3), ...u16le(cmd), ...u16le(sub)]
}

/** CallArg::Pure(Vec<u8>). */
function pureInput(bytes: number[]): number[] {
  return [...uleb(0), ...uleb(bytes.length), ...bytes]
}
/** CallArg::Object::ImmOrOwnedObject(ObjectRef). */
function ownedObjectInput(objectId: string, version: bigint, digest: string): number[] {
  return [
    ...uleb(1), // CallArg::Object
    ...uleb(0), // ObjectArg::ImmOrOwnedObject
    ...address(objectId),
    ...u64le(version),
    ...address(digest),
  ]
}

/** Command::MoveCall(pkg::module::function, ty_args, args). */
function moveCall(
  pkg: string,
  mod: string,
  fn: string,
  args: number[][] = [],
  tyArgs: number[][] = [],
): number[] {
  const bytes: number[] = []
  bytes.push(...uleb(0)) // tag = MoveCall
  bytes.push(...address(pkg))
  bytes.push(...bcsStr(mod))
  bytes.push(...bcsStr(fn))
  bytes.push(...uleb(tyArgs.length))
  for (const t of tyArgs) bytes.push(...t)
  bytes.push(...uleb(args.length))
  for (const a of args) bytes.push(...a)
  return bytes
}

/** Command::TransferObjects(objects, recipient). */
function transferObjects(objects: number[][], recipient: number[]): number[] {
  const bytes: number[] = []
  bytes.push(...uleb(1))
  bytes.push(...uleb(objects.length))
  for (const o of objects) bytes.push(...o)
  bytes.push(...recipient)
  return bytes
}

/** Command::SplitCoins(source, amounts). */
function splitCoins(source: number[], amounts: number[][]): number[] {
  const bytes: number[] = []
  bytes.push(...uleb(2))
  bytes.push(...source)
  bytes.push(...uleb(amounts.length))
  for (const a of amounts) bytes.push(...a)
  return bytes
}

/** Command::MergeCoins(dest, sources). */
function mergeCoins(dest: number[], sources: number[][]): number[] {
  const bytes: number[] = []
  bytes.push(...uleb(3))
  bytes.push(...dest)
  bytes.push(...uleb(sources.length))
  for (const s of sources) bytes.push(...s)
  return bytes
}

/** Command::Publish(modules, deps). */
function publish(modules: number[][], deps: string[]): number[] {
  const bytes: number[] = []
  bytes.push(...uleb(4))
  bytes.push(...uleb(modules.length))
  for (const m of modules) {
    bytes.push(...uleb(m.length))
    bytes.push(...m)
  }
  bytes.push(...uleb(deps.length))
  for (const d of deps) bytes.push(...address(d))
  return bytes
}

/** TypeTag::Struct(0x2::sui::SUI). */
function typeTagSUI(): number[] {
  const bytes: number[] = []
  bytes.push(...uleb(7)) // Struct
  bytes.push(...address('02')) // 0x2
  bytes.push(...bcsStr('sui'))
  bytes.push(...bcsStr('SUI'))
  bytes.push(...uleb(0)) // no nested type args
  return bytes
}

/** Build a complete TransactionData::V1(ProgrammableTransaction) payload. */
function buildTx(
  inputs: number[][],
  commands: number[][],
  sender: number[] = SENDER,
): string {
  const bytes: number[] = []
  bytes.push(...uleb(0)) // TransactionData::V1
  bytes.push(...uleb(0)) // TransactionKind::ProgrammableTransaction
  bytes.push(...uleb(inputs.length))
  for (const inp of inputs) bytes.push(...inp)
  bytes.push(...uleb(commands.length))
  for (const c of commands) bytes.push(...c)
  bytes.push(...sender)
  return `0x${Buffer.from(bytes).toString('hex')}`
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe('suiDecoder', () => {
  it('decodes a plain SplitCoins + TransferObjects as no-special-risk', () => {
    // SplitCoins(GasCoin, [Pure(amount)]) → Result(0) → TransferObjects([R0], Pure(recipient))
    const amount = pureInput(u64le(1_000_000_000n)) // 1 SUI
    const recipient = pureInput([...address('beef')])
    const tx = buildTx(
      [amount, recipient],
      [
        splitCoins(gasCoin(), [inputArg(0)]),
        transferObjects([resultArg(0)], inputArg(1)),
      ],
    )

    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('sender 0xa1b2c3')
    expect(r.reasons.join(' ')).toContain('TransferObjects')
    expect(r.reasons.join(' ')).toContain('SplitCoins')
  })

  it('treats built-in 0x2::pay::split_and_transfer as no-special-risk', () => {
    const recipient = pureInput([...address('beef')])
    const amount = pureInput(u64le(500n))
    const tx = buildTx(
      [recipient, amount],
      [
        moveCall(
          '02',
          'pay',
          'split_and_transfer',
          [gasCoin(), inputArg(1), inputArg(0)],
          [typeTagSUI()],
        ),
      ],
    )

    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('0x2::pay::split_and_transfer')
  })

  it('flags a Move call to a non-builtin package as medium', () => {
    // Cetus-like router call (random package address). Decoder cannot verify
    // its effects → medium with the package surfaced in `reasons`.
    const coinIn = ownedObjectInput('cafe', 42n, 'd00d')
    const tx = buildTx(
      [coinIn],
      [
        moveCall(
          '1eabcd', // arbitrary third-party package
          'router',
          'swap_a_to_b',
          [inputArg(0)],
        ),
      ],
    )

    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('0x1eabcd::router::swap_a_to_b')
    expect(r.reasons.join(' ')).toContain('non-builtin')
  })

  it('flags a Publish command as high', () => {
    const tx = buildTx([], [publish([[0xde, 0xad]], ['01'])])
    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.level).toBe('high')
    expect(r.reasons.join(' ')).toContain('Publish')
  })

  it('marks an empty programmable tx as medium', () => {
    const tx = buildTx([], [])
    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.level).toBe('medium')
    expect(r.reasons.join(' ')).toContain('zero commands')
  })

  it('degrades honestly on an undecodable payload', () => {
    // ULEB-encoded version=1 → unsupported branch ⇒ unverifiable.
    const r = suiDecoder.decode('0x01', 'transaction', ctx)
    expect(r.effectsExtracted).toBe(false)
    expect(r.level).toBe('critical')
  })

  it('treats a message-kind payload as a low-risk signature', () => {
    const r = suiDecoder.decode('0xdeadbeef', 'message', ctx)
    expect(r.level).toBe('none')
    expect(r.effectsExtracted).toBe(true)
  })

  it('parses mixed MoveCall + transfer correctly and reports both', () => {
    // 0x2::pay::join_vec + plain TransferObjects. join_vec is built-in; the
    // overall level should be 'none' (every MoveCall is in TRANSFER_FUNCTIONS).
    const coinA = ownedObjectInput('aaaa', 1n, 'bbbb')
    const coinB = ownedObjectInput('cccc', 2n, 'dddd')
    const recipient = pureInput([...address('beef')])
    const tx = buildTx(
      [coinA, coinB, recipient],
      [
        moveCall(
          '02',
          'pay',
          'join_vec',
          [inputArg(0), inputArg(1)],
          [typeTagSUI()],
        ),
        transferObjects([inputArg(0)], inputArg(2)),
      ],
    )

    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.level).toBe('none')
    expect(r.reasons.join(' ')).toContain('0x2::pay::join_vec')
    expect(r.reasons.join(' ')).toContain('TransferObjects')
  })

  it('uses nested-result arguments without crashing', () => {
    // SplitCoins(GasCoin, [Pure(a), Pure(b)]) → 2 results → MoveCall on them.
    const a = pureInput(u64le(1n))
    const b = pureInput(u64le(2n))
    const tx = buildTx(
      [a, b],
      [
        splitCoins(gasCoin(), [inputArg(0), inputArg(1)]),
        moveCall(
          '02',
          'pay',
          'join',
          [nestedResult(0, 0), nestedResult(0, 1)],
          [typeTagSUI()],
        ),
      ],
    )

    const r = suiDecoder.decode(tx, 'transaction', ctx)
    expect(r.effectsExtracted).toBe(true)
    expect(r.level).toBe('none')
  })
})
