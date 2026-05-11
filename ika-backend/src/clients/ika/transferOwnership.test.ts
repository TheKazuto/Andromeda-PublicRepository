import { describe, it, expect } from 'vitest'
import { AccountRole, generateKeyPairSigner, getAddressEncoder } from '@solana/kit'

import { buildTransferOwnershipInstruction, IKA_IX_TRANSFER_OWNERSHIP } from './transferOwnership.js'

const IKA_PROGRAM_ID = '87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY'

describe('ika/transferOwnership — disc 24 direct-call instruction', () => {
  it('encodes [24, new_authority(32)] = 33 bytes and the 2-account layout', async () => {
    const authoritySigner = await generateKeyPairSigner()
    const newAuthoritySigner = await generateKeyPairSigner()
    const dwalletSigner = await generateKeyPairSigner()

    const ix = buildTransferOwnershipInstruction({
      ikaProgramId: IKA_PROGRAM_ID,
      dwallet: dwalletSigner.address,
      authoritySigner,
      newAuthority: newAuthoritySigner.address,
    })

    expect(ix.programAddress).toBe(IKA_PROGRAM_ID)

    // data: discriminator + 32-byte new authority
    expect(ix.data).toBeDefined()
    const data = ix.data as Uint8Array
    expect(data).toHaveLength(33)
    expect(data[0]).toBe(IKA_IX_TRANSFER_OWNERSHIP)
    expect(data[0]).toBe(24)
    const expectedNewAuth = Uint8Array.from(getAddressEncoder().encode(newAuthoritySigner.address))
    expect(Buffer.from(data.slice(1))).toEqual(Buffer.from(expectedNewAuth))

    // accounts: [authority (RO signer, carries the signer), dwallet (W)]
    expect(ix.accounts).toBeDefined()
    const accounts = ix.accounts as ReadonlyArray<{ address: string; role: AccountRole; signer?: unknown }>
    expect(accounts).toHaveLength(2)
    expect(accounts[0]?.address).toBe(authoritySigner.address)
    expect(accounts[0]?.role).toBe(AccountRole.READONLY_SIGNER)
    expect(accounts[0]?.signer).toBe(authoritySigner)
    expect(accounts[1]?.address).toBe(dwalletSigner.address)
    expect(accounts[1]?.role).toBe(AccountRole.WRITABLE)
    expect(accounts[1]?.signer).toBeUndefined()
  })
})
