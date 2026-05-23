import { describe, expect, it } from 'vitest'
import { address, AccountRole, type Address } from '@solana/kit'

import {
  buildAddRuleAllowlistInstruction,
  buildAddRuleFheGatedInstruction,
  buildAddRuleOracleInstruction,
  buildAddRulePasskeyInstruction,
  buildAddRuleSessionKeyInstruction,
  buildAddRuleTimeLockInstruction,
  buildAddRuleVelocityInstruction,
  buildCloseExpiredSessionInstruction,
  buildInitEngineInstruction,
  buildRecoverAsPrimaryInstruction,
  buildRequestSignatureInstruction,
  buildRequestSignatureViaSessionInstruction,
  buildSessionAddDestinationInstruction,
  buildSessionCloseInstruction,
  buildSessionOpenInstruction,
  buildSessionRemoveDestinationInstruction,
  buildSessionRevokeInstruction,
  buildUpdateAllowlistAddDestinationInstruction,
  buildUpdateRecoveryAddDestinationInstruction,
  buildUpdateRecoveryAddMemberInstruction,
} from '../instructions.js'
import {
  APPLIES_NORMAL,
  APPLIES_SESSION,
  MEMBER_SLOT_LEN,
  POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR,
} from '../program.js'

const TEST_PROGRAM = address('ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL') as Address
const TEST_ENGINE = address('9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4') as Address
const TEST_DWALLET = address('4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14') as Address
const TEST_PAYER = address('11111111111111111111111111111112') as Address

function makeSlot(seed: number): Uint8Array {
  const slot = new Uint8Array(MEMBER_SLOT_LEN)
  slot[0] = 0 // Ed25519
  for (let i = 1; i < MEMBER_SLOT_LEN; i += 1) slot[i] = (seed + i) & 0xff
  return slot
}

function fill32(seed: number): Uint8Array {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i += 1) out[i] = (seed + i) & 0xff
  return out
}

describe('PolicyEngine v3 instruction builders (F2.4b)', () => {
  it('buildInitEngineInstruction has the expected data layout', async () => {
    const initSlot = makeSlot(0x10)
    const ownerSlot = makeSlot(0x20)
    const initHash = fill32(0x30)
    const recoveryHash = new Uint8Array(32)

    const ix = await buildInitEngineInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthoritySlot: initSlot,
      initAuthorityHash: initHash,
      ownerSlot,
      defaultRecoveryPresent: 0,
      defaultRecoveryHash: recoveryHash,
    })

    expect(ix.programAddress).toBe(TEST_PROGRAM)
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.initEngine)
    // expected ix data: 1 (disc) + 34 + 32 + 34 + 1 + 32 = 134
    expect(ix.data?.length).toBe(134)
    // init_authority_slot at offset 1..35
    expect(Array.from(ix.data!.slice(1, 1 + MEMBER_SLOT_LEN))).toEqual(Array.from(initSlot))
    // 9 fixed accounts in init_engine (no rule_recovery_pda when present=0)
    expect(ix.accounts?.length).toBe(9)
    // payer (index 2) must be writable signer.
    expect(ix.accounts?.[2]?.address).toBe(TEST_PAYER)
  })

  it('buildAddRuleAllowlistInstruction has the expected data layout', async () => {
    const initHash = fill32(0x40)
    const ix = await buildAddRuleAllowlistInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: initHash,
      expectedNonce: 7n,
      ruleIndex: 0,
      appliesTo: APPLIES_NORMAL,
    })

    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleAllowlist)
    // 1 (disc) + 32 + 8 + 1 + 1 = 43
    expect(ix.data?.length).toBe(43)
    // expected_nonce LE at offset 33..41
    const dv = new DataView(ix.data!.buffer, ix.data!.byteOffset + 33, 8)
    expect(dv.getBigUint64(0, true)).toBe(7n)
    expect(ix.data?.[41]).toBe(0) // rule_index
    expect(ix.data?.[42]).toBe(APPLIES_NORMAL)
    expect(ix.accounts?.length).toBe(10)
  })

  it('buildUpdateAllowlistAddDestinationInstruction has the expected data layout', async () => {
    const initHash = fill32(0x50)
    const dest = fill32(0xaa)
    const ix = await buildUpdateAllowlistAddDestinationInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: initHash,
      expectedNonce: 1n,
      ruleIndex: 0,
      destination: dest,
    })

    expect(ix.data?.[0]).toBe(
      POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleAllowlistAddDestination,
    )
    // 1 + 32 + 8 + 1 + 32 = 74
    expect(ix.data?.length).toBe(74)
    expect(Array.from(ix.data!.slice(42, 74))).toEqual(Array.from(dest))
    expect(ix.accounts?.length).toBe(9)
  })

  it('buildRequestSignatureInstruction has the expected data layout', async () => {
    const ika = address('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY') as Address
    const coordinator = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpY') as Address
    const messageApproval = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpZ' as string) as Address
    const cpiAuth = address('11111111111111111111111111111113') as Address
    const callerProgram = address('11111111111111111111111111111114') as Address
    const rule0 = address('11111111111111111111111111111115') as Address

    const ix = await buildRequestSignatureInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      coordinator,
      messageApproval,
      payer: TEST_PAYER,
      cpiAuthority: cpiAuth,
      callerProgram,
      dwalletProgram: ika,
      rulePdas: [rule0],
      initAuthorityHash: fill32(0x60),
      messageDigest: fill32(0x70),
      metadataDigest: fill32(0x80),
      userPubkey: fill32(0x90),
      signatureScheme: 0,
      messageApprovalBump: 254,
      cpiAuthorityBump: 253,
      destination: fill32(0xa0),
      rulesGenerationSeen: 3,
    })

    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.requestSignature)
    // ABI V3 (Update 6): 1 (disc) + 32 + 32 + 32 + 32 + 2 + 1 + 1 + 32 + 4
    // + 8 (amount) + 1 (asset_index) + 32 (ika_msg_metadata_digest) = 210
    expect(ix.data?.length).toBe(210)
    expect(ix.data?.[129]).toBe(0) // signature_scheme LE byte 0
    expect(ix.data?.[131]).toBe(254) // message_approval_bump
    expect(ix.data?.[132]).toBe(253) // cpi_authority_bump
    // amount (u64 LE) at offset 169, asset_index (u8) at offset 177; both 0 here.
    expect(ix.data?.[169]).toBe(0)
    expect(ix.data?.[177]).toBe(0)
    // ika_msg_metadata_digest (32 bytes) at offset 178; zero by default here.
    expect(ix.data?.[178]).toBe(0)
    expect(ix.data?.[209]).toBe(0)
    // 12 declared + 1 remaining (rule slot 0) = 13
    expect(ix.accounts?.length).toBe(13)
  })

  it('buildRequestSignatureInstruction supports multi-rule remaining_accounts (F8a)', async () => {
    const ika = address('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY') as Address
    const coordinator = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpY') as Address
    const messageApproval = address(
      '5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpZ' as string,
    ) as Address
    const cpiAuth = address('11111111111111111111111111111113') as Address
    const callerProgram = address('11111111111111111111111111111114') as Address
    const rule0 = address('11111111111111111111111111111115') as Address
    const rule1 = address('11111111111111111111111111111116') as Address
    const rule2 = address('11111111111111111111111111111117') as Address

    const ix = await buildRequestSignatureInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      coordinator,
      messageApproval,
      payer: TEST_PAYER,
      cpiAuthority: cpiAuth,
      callerProgram,
      dwalletProgram: ika,
      rulePdas: [rule0, rule1, rule2],
      initAuthorityHash: fill32(0),
      messageDigest: fill32(0),
      metadataDigest: fill32(0),
      userPubkey: fill32(0),
      signatureScheme: 0,
      messageApprovalBump: 0,
      cpiAuthorityBump: 0,
      destination: fill32(0),
      rulesGenerationSeen: 0,
    })
    // 12 declared + 3 remaining
    expect(ix.accounts?.length).toBe(15)
    // Trailing accounts must be writable so kinds with mutable counters
    // (Velocity, SessionKey, Recovery) can write back via `data_ptr()`.
    expect(ix.accounts?.[12]?.role).toBe(AccountRole.WRITABLE)
    expect(ix.accounts?.[13]?.role).toBe(AccountRole.WRITABLE)
    expect(ix.accounts?.[14]?.role).toBe(AccountRole.WRITABLE)
    expect(ix.accounts?.[12]?.address).toBe(rule0)
    expect(ix.accounts?.[13]?.address).toBe(rule1)
    expect(ix.accounts?.[14]?.address).toBe(rule2)
  })

  it('buildRequestSignatureInstruction works with zero active rules', async () => {
    const ika = address('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY') as Address
    const coordinator = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpY') as Address
    const messageApproval = address(
      '5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpZ' as string,
    ) as Address
    const cpiAuth = address('11111111111111111111111111111113') as Address
    const callerProgram = address('11111111111111111111111111111114') as Address
    const ix = await buildRequestSignatureInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      coordinator,
      messageApproval,
      payer: TEST_PAYER,
      cpiAuthority: cpiAuth,
      callerProgram,
      dwalletProgram: ika,
      rulePdas: [],
      initAuthorityHash: fill32(0),
      messageDigest: fill32(0),
      metadataDigest: fill32(0),
      userPubkey: fill32(0),
      signatureScheme: 0,
      messageApprovalBump: 0,
      cpiAuthorityBump: 0,
      destination: fill32(0),
      rulesGenerationSeen: 0,
    })
    expect(ix.accounts?.length).toBe(12)
  })

  it('rejects caller_program === programId', async () => {
    await expect(
      buildRequestSignatureInstruction({
        programId: TEST_PROGRAM,
        dwallet: TEST_DWALLET,
        engine: TEST_ENGINE,
        coordinator: TEST_PROGRAM,
        messageApproval: TEST_PROGRAM,
        payer: TEST_PAYER,
        cpiAuthority: TEST_PROGRAM,
        callerProgram: TEST_PROGRAM, // <- collision
        dwalletProgram: TEST_PROGRAM,
        rulePdas: [],
        initAuthorityHash: fill32(0),
        messageDigest: fill32(0),
        metadataDigest: fill32(0),
        userPubkey: fill32(0),
        signatureScheme: 0,
        messageApprovalBump: 0,
        cpiAuthorityBump: 0,
        destination: fill32(0),
        rulesGenerationSeen: 0,
      }),
    ).rejects.toThrow(/caller_program must NOT equal programId/)
  })

  it('buildAddRuleVelocityInstruction has the expected data layout (F3)', async () => {
    const ix = await buildAddRuleVelocityInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0x80),
      expectedNonce: 0n,
      ruleIndex: 0,
      appliesTo: APPLIES_NORMAL,
      windows: [{ windowSeconds: 60n, cap: 5n }],
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleVelocity)
    // 1 + 32 + 8 + 1 + 1 + 1 + 64 = 108
    expect(ix.data?.length).toBe(108)
    expect(ix.data?.[42]).toBe(APPLIES_NORMAL)
    expect(ix.data?.[43]).toBe(1) // windows_count
    // window 0 window_seconds at offset 44..52
    const dv = new DataView(ix.data!.buffer, ix.data!.byteOffset + 44, 16)
    expect(dv.getBigUint64(0, true)).toBe(60n)
    expect(dv.getBigUint64(8, true)).toBe(5n)
    expect(ix.accounts?.length).toBe(10)
  })

  it('buildAddRuleVelocityInstruction rejects empty windows', async () => {
    await expect(
      buildAddRuleVelocityInstruction({
        programId: TEST_PROGRAM,
        dwallet: TEST_DWALLET,
        engine: TEST_ENGINE,
        payer: TEST_PAYER,
        initAuthorityHash: fill32(0),
        expectedNonce: 0n,
        ruleIndex: 0,
        appliesTo: APPLIES_NORMAL,
        windows: [],
      }),
    ).rejects.toThrow(/1\.\.4/)
  })

  it('buildAddRuleTimeLockInstruction (F4) layout', async () => {
    const ix = await buildAddRuleTimeLockInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0xa0),
      expectedNonce: 0n,
      ruleIndex: 0,
      appliesTo: APPLIES_NORMAL,
      mode: 0,
      unlockTs: 1_800_000_000n,
      delaySeconds: 0n,
    })
    // 1 + 32 + 8 + 1 + 1 + 1 + 8 + 8 = 60
    expect(ix.data?.length).toBe(60)
    expect(ix.data?.[43]).toBe(0) // mode
  })

  it('buildAddRuleOracleInstruction (F5) layout', async () => {
    const ix = await buildAddRuleOracleInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0xb0),
      expectedNonce: 0n,
      ruleIndex: 0,
      appliesTo: APPLIES_NORMAL,
      freshnessSecondsDiv16: 4,
      minConfidenceBpsDiv4: 2,
    })
    expect(ix.data?.length).toBe(45)
  })

  it('buildAddRulePasskeyInstruction (F6) layout', async () => {
    const ix = await buildAddRulePasskeyInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0xc0),
      expectedNonce: 0n,
      ruleIndex: 0,
      appliesTo: APPLIES_NORMAL,
    })
    expect(ix.data?.length).toBe(43)
  })

  it('buildAddRuleFheGatedInstruction (F7) layout', async () => {
    const ix = await buildAddRuleFheGatedInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0xd0),
      expectedNonce: 0n,
      ruleIndex: 0,
      appliesTo: APPLIES_NORMAL,
      freshnessSecondsDiv16: 8,
    })
    expect(ix.data?.length).toBe(44)
  })

  it('rejects default_recovery_present=1 (F9 scope)', async () => {
    await expect(
      buildInitEngineInstruction({
        programId: TEST_PROGRAM,
        dwallet: TEST_DWALLET,
        engine: TEST_ENGINE,
        payer: TEST_PAYER,
        initAuthoritySlot: makeSlot(0),
        initAuthorityHash: fill32(0),
        ownerSlot: makeSlot(1),
        defaultRecoveryPresent: 1,
        defaultRecoveryHash: fill32(2),
      }),
    ).rejects.toThrow(/F9 scope/)
  })

  // ── F8b — SessionKey builders ──────────────────────────────────────────

  // ── F11 — policyEngineInitChallenge ────────────────────────────────────

  it('policyEngineInitChallenge differs by defaultRecoveryPresent (F11)', async () => {
    const { policyEngineInitChallenge } = await import('../challenges.js')
    const dwallet = TEST_DWALLET
    const initAuthSlot = makeSlot(1)
    const ownerSlot = makeSlot(2)
    const empty = new Uint8Array(32)
    const recoveryHash = new Uint8Array(32).fill(0xaa)

    const plain = policyEngineInitChallenge({
      dwallet,
      initAuthoritySlot: initAuthSlot,
      ownerSlot,
      defaultRecoveryPresent: 0,
      defaultRecoveryHash: empty,
    })
    const withRecovery = policyEngineInitChallenge({
      dwallet,
      initAuthoritySlot: initAuthSlot,
      ownerSlot,
      defaultRecoveryPresent: 1,
      defaultRecoveryHash: recoveryHash,
    })
    // Hashes must be 32 bytes, deterministic, and different (op_tag changes).
    expect(plain.length).toBe(32)
    expect(withRecovery.length).toBe(32)
    expect(Buffer.from(plain).equals(Buffer.from(withRecovery))).toBe(false)

    // Re-running with same input is stable.
    const plainAgain = policyEngineInitChallenge({
      dwallet,
      initAuthoritySlot: initAuthSlot,
      ownerSlot,
      defaultRecoveryPresent: 0,
      defaultRecoveryHash: empty,
    })
    expect(Buffer.from(plain).equals(Buffer.from(plainAgain))).toBe(true)
  })

  it('buildAddRuleSessionKeyInstruction has the expected data layout (F8b)', async () => {
    const ix = await buildAddRuleSessionKeyInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0x10),
      expectedNonce: 0n,
      ruleIndex: 0,
      appliesTo: APPLIES_SESSION,
      maxSessions: 4,
      defaultTtlSeconds: 3600n,
      defaultMaxUses: 100,
      sessionMaxAmountPerTx: 1_000_000n,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.addRuleSessionKey)
    // 1 (disc) + 32 (hash) + 8 (nonce) + 1 + 1 + 1 + 8 + 4 + 8 = 64
    expect(ix.data?.length).toBe(64)
    expect(ix.data?.[42]).toBe(APPLIES_SESSION)
    expect(ix.data?.[43]).toBe(4) // maxSessions
    expect(ix.accounts?.length).toBe(10)
  })

  it('buildSessionOpenInstruction has the expected data layout (F8b)', async () => {
    const signer = address('11111111111111111111111111111119') as Address
    const ix = await buildSessionOpenInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0x20),
      expectedNonce: 1n,
      ruleIndex: 0,
      sessionIndex: 0,
      sessionSigner: signer,
      expiresAtTs: 1_800n,
      maxUses: 10,
      maxAmountPerTx: 500n,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionOpen)
    // 1 + 32 + 8 + 1 + 4 + 32 + 8 + 4 + 8 = 98
    expect(ix.data?.length).toBe(98)
    expect(ix.accounts?.length).toBe(11)
  })

  it('buildRequestSignatureViaSessionInstruction has the expected layout (F8b)', async () => {
    const ika = address('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY') as Address
    const coordinator = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpY') as Address
    const messageApproval = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpZ' as string) as Address
    const cpiAuth = address('11111111111111111111111111111113') as Address
    const callerProgram = address('11111111111111111111111111111114') as Address
    const sessionSigner = address('11111111111111111111111111111119') as Address

    const ix = await buildRequestSignatureViaSessionInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      sessionSigner,
      coordinator,
      messageApproval,
      payer: TEST_PAYER,
      cpiAuthority: cpiAuth,
      callerProgram,
      dwalletProgram: ika,
      initAuthorityHash: fill32(0x30),
      sessionIndex: 0,
      messageDigest: fill32(0x40),
      metadataDigest: fill32(0x50),
      userPubkey: fill32(0x60),
      signatureScheme: 0,
      messageApprovalBump: 0xfe,
      cpiAuthorityBump: 0xfd,
      destination: fill32(0x70),
      expectedSignatureNonce: 0n,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.requestSignatureViaSession)
    // 1 + 32 + 4 + 32 + 32 + 32 + 2 + 1 + 1 + 32 + 8 = 177
    expect(ix.data?.length).toBe(177)
    // 14 declared accounts (no remaining_accounts on the session path).
    expect(ix.accounts?.length).toBe(14)
    // session_signer (index 3) must be READONLY_SIGNER.
    expect(ix.accounts?.[3]?.role).toBe(AccountRole.READONLY_SIGNER)
  })

  // ── F8c — session lifecycle builders ───────────────────────────────────

  it('buildSessionRevokeInstruction has the expected layout (F8c)', async () => {
    const ix = await buildSessionRevokeInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0),
      sessionIndex: 0,
      expectedNonce: 0n,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionRevoke)
    // 1 + 32 + 4 + 8 = 45
    expect(ix.data?.length).toBe(45)
    expect(ix.accounts?.length).toBe(8) // no recipient
  })

  it('buildSessionCloseInstruction has the expected layout (F8c)', async () => {
    const recipient = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpY') as Address
    const ix = await buildSessionCloseInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      recipient,
      initAuthorityHash: fill32(0),
      sessionIndex: 0,
      expectedNonce: 1n,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionClose)
    expect(ix.data?.length).toBe(45)
    // 9 accounts (recipient slot included).
    expect(ix.accounts?.length).toBe(9)
    expect(ix.accounts?.[3]?.address).toBe(recipient)
    expect(ix.accounts?.[3]?.role).toBe(AccountRole.WRITABLE)
  })

  it('buildCloseExpiredSessionInstruction has the expected layout (F8c)', async () => {
    const recipient = address('4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14') as Address
    const ix = await buildCloseExpiredSessionInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      recipient,
      initAuthorityHash: fill32(0),
      sessionIndex: 0,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.closeExpiredSession)
    // 1 + 32 + 4 = 37 (no nonce — permissionless)
    expect(ix.data?.length).toBe(37)
    expect(ix.accounts?.length).toBe(9)
  })

  it('buildSessionAddDestinationInstruction has the expected layout (F8c)', async () => {
    const ix = await buildSessionAddDestinationInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0),
      sessionIndex: 0,
      expectedNonce: 2n,
      destination: fill32(0xaa),
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionAddDestination)
    // 1 + 32 + 4 + 8 + 32 = 77
    expect(ix.data?.length).toBe(77)
    expect(ix.accounts?.length).toBe(8)
  })

  it('buildSessionRemoveDestinationInstruction has the expected layout (F8c)', async () => {
    const ix = await buildSessionRemoveDestinationInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0),
      sessionIndex: 0,
      expectedNonce: 3n,
      destination: fill32(0xbb),
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.sessionRemoveDestination)
    expect(ix.data?.length).toBe(77)
    expect(ix.accounts?.length).toBe(8)
  })

  // ── F9a — Recovery builders ────────────────────────────────────────────

  it('buildUpdateRecoveryAddMemberInstruction has the expected layout (F9a)', async () => {
    const ix = await buildUpdateRecoveryAddMemberInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0),
      expectedNonce: 0n,
      ruleIndex: 0,
      memberSlot: makeSlot(7),
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleRecoveryAddMember)
    // 1 + 32 + 8 + 1 + 34 = 76
    expect(ix.data?.length).toBe(76)
    expect(ix.accounts?.length).toBe(9)
  })

  it('buildUpdateRecoveryAddDestinationInstruction has the expected layout (F9a)', async () => {
    const ix = await buildUpdateRecoveryAddDestinationInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      payer: TEST_PAYER,
      initAuthorityHash: fill32(0),
      expectedNonce: 1n,
      ruleIndex: 0,
      destination: fill32(0xcc),
    })
    expect(ix.data?.[0]).toBe(
      POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.updateRuleRecoveryAddDestination,
    )
    // 1 + 32 + 8 + 1 + 32 = 74
    expect(ix.data?.length).toBe(74)
    expect(ix.accounts?.length).toBe(9)
  })

  it('buildRecoverAsPrimaryInstruction has the expected layout (F9a)', async () => {
    const ika = address('87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY') as Address
    const coordinator = address('5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpY') as Address
    const messageApproval = address(
      '5gB9bbg7ymRZsYUKb24cs7yPSHnVJgQpyJjcvTNXTcpZ' as string,
    ) as Address
    const cpiAuth = address('11111111111111111111111111111113') as Address
    const callerProgram = address('11111111111111111111111111111114') as Address

    const ix = await buildRecoverAsPrimaryInstruction({
      programId: TEST_PROGRAM,
      dwallet: TEST_DWALLET,
      engine: TEST_ENGINE,
      coordinator,
      messageApproval,
      payer: TEST_PAYER,
      cpiAuthority: cpiAuth,
      callerProgram,
      dwalletProgram: ika,
      initAuthorityHash: fill32(0),
      ruleIndex: 0,
      messageDigest: fill32(0x10),
      metadataDigest: fill32(0x20),
      userPubkey: fill32(0x30),
      signatureScheme: 0,
      messageApprovalBump: 0xff,
      cpiAuthorityBump: 0xfe,
      destination: fill32(0x40),
      expectedNonce: 0n,
      amount: 1_000_000n,
    })
    expect(ix.data?.[0]).toBe(POLICY_ENGINE_INSTRUCTION_DISCRIMINATOR.recoverAsPrimary)
    // 1 + 32 + 1 + 32 + 32 + 32 + 2 + 1 + 1 + 32 + 8 + 8 = 182
    expect(ix.data?.length).toBe(182)
    expect(ix.accounts?.length).toBe(14)
  })
})
