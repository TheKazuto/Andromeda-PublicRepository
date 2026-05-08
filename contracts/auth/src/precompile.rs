//! Reads the Instructions sysvar and finds Ed25519 / Secp256k1 / Secp256r1
//! precompile invocations whose `(public_key_or_eth_address, message)` match
//! an expected pair.
//!
//! ─── Ed25519 / Secp256r1 layout ────────────────────────────────────────
//! Header (2 bytes): `num_records (u8) || padding (u8)`.
//! Each offsets record is 14 bytes:
//! ```text
//! [0..2]   signature_offset (u16 LE)
//! [2..4]   signature_instruction_index (u16 LE)
//! [4..6]   public_key_offset (u16 LE)
//! [6..8]   public_key_instruction_index (u16 LE)
//! [8..10]  message_data_offset (u16 LE)
//! [10..12] message_data_size (u16 LE)
//! [12..14] message_instruction_index (u16 LE)
//! ```
//! Self-reference sentinel: `0xFFFF` (u16).
//!
//! ─── Secp256k1 layout ─────────────────────────────────────────────────
//! Header (1 byte): `num_records (u8)`.
//! Each offsets record is 11 bytes:
//! ```text
//! [0..2]   signature_offset (u16 LE)
//! [2]      signature_instruction_index (u8)
//! [3..5]   eth_address_offset (u16 LE)
//! [5]      eth_address_instruction_index (u8)
//! [6..8]   message_data_offset (u16 LE)
//! [8..10]  message_data_size (u16 LE)
//! [10]     message_instruction_index (u8)
//! ```
//! Self-reference sentinel: `0xFF` (u8). Signatures are 64 bytes followed by a
//! 1-byte recovery_id (65 total). The expected identifier is the 20-byte
//! eth_address (`keccak256(uncompressed_pubkey)[12..]`).
//!
//! All callers must require self-contained invocations; cross-instruction
//! references are rejected.

use solana_address::Address;

// Stored as raw bytes (not `from_str_const(...)`) because the base58
// decoder used in const context overflows the SBF const-eval budget on
// some pubkeys ("Largest term greater than 2^32"). The byte arrays below
// decode to the strings shown in the comment, verified at audit time.

/// `Sysvar1nstructions1111111111111111111111111`.
pub const INSTRUCTIONS_SYSVAR_ID: Address = Address::new_from_array([
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0x7b, 0xd1, 0x66, 0x35, 0xda, 0xd4, 0x04, 0x55, 0xfd, 0xc2, 0xc0,
    0xc1, 0x24, 0xc6, 0x8f, 0x21, 0x56, 0x75, 0xa5, 0xdb, 0xba, 0xcb, 0x5f, 0x08, 0x00, 0x00, 0x00,
]);

/// `Ed25519SigVerify111111111111111111111111111`.
pub const ED25519_PRECOMPILE_ID: Address = Address::new_from_array([
    0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe, 0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40, 0xff,
    0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64, 0xfc, 0xca, 0x70, 0x44, 0x80, 0x00, 0x00, 0x00,
]);

/// `KeccakSecp256k11111111111111111111111111111`.
pub const SECP256K1_PRECOMPILE_ID: Address = Address::new_from_array([
    0x04, 0xc6, 0xfc, 0x20, 0xf0, 0x50, 0xcc, 0xf0, 0x55, 0x84, 0xd7, 0x21, 0x1c, 0x9f, 0x8c, 0xf5,
    0x9e, 0xc1, 0x47, 0x85, 0xbb, 0x16, 0x6a, 0x1e, 0x28, 0x30, 0xe8, 0x12, 0x20, 0x00, 0x00, 0x00,
]);

/// `Secp256r1SigVerify1111111111111111111111111`.
pub const SECP256R1_PRECOMPILE_ID: Address = Address::new_from_array([
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5, 0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56, 0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
]);

const LONG_SELF_INDEX: u16 = 0xFFFF;
const SHORT_SELF_INDEX: u8 = 0xFF;
const LONG_OFFSETS_LEN: usize = 14;
const SHORT_OFFSETS_LEN: usize = 11;
const ACCOUNT_META_LEN: usize = 33;
const PROGRAM_ID_LEN: usize = 32;

pub const ED25519_SIG_LEN: usize = 64;
pub const ED25519_PUBKEY_LEN: usize = 32;
pub const SECP256K1_SIG_LEN: usize = 64;
pub const SECP256K1_RECID_LEN: usize = 1;
pub const SECP256K1_ETH_ADDR_LEN: usize = 20;
pub const SECP256R1_SIG_LEN: usize = 64;
pub const SECP256R1_PUBKEY_LEN: usize = 33;

#[derive(Debug)]
pub enum PrecompileError {
    InvalidSysvarAddress,
    SysvarTooShort,
    InvalidLayout,
    CrossInstructionUnsupported,
    NoMatchingInvocation,
}

#[inline]
pub fn check_sysvar_address(addr: &Address) -> Result<(), PrecompileError> {
    if addr.as_array() != INSTRUCTIONS_SYSVAR_ID.as_array() {
        return Err(PrecompileError::InvalidSysvarAddress);
    }
    Ok(())
}

#[inline]
fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, PrecompileError> {
    let end = offset.checked_add(2).ok_or(PrecompileError::SysvarTooShort)?;
    if end > buf.len() {
        return Err(PrecompileError::SysvarTooShort);
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

#[inline]
fn read_u8(buf: &[u8], offset: usize) -> Result<u8, PrecompileError> {
    if offset >= buf.len() {
        return Err(PrecompileError::SysvarTooShort);
    }
    Ok(buf[offset])
}

#[inline]
fn read_slice<'a>(buf: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8], PrecompileError> {
    let end = offset.checked_add(len).ok_or(PrecompileError::SysvarTooShort)?;
    if end > buf.len() {
        return Err(PrecompileError::SysvarTooShort);
    }
    Ok(&buf[offset..end])
}

/// Iterates over instructions in `sysvar_data` looking for the body of the
/// `i`-th instruction. Returns `(program_id_slice, data_slice)` for that
/// instruction body, or `None` if `i` is out of range.
fn read_ix_body(sysvar_data: &[u8], i: usize) -> Result<Option<(&[u8], &[u8])>, PrecompileError> {
    if sysvar_data.len() < 2 {
        return Err(PrecompileError::SysvarTooShort);
    }
    let num_instructions = read_u16_le(sysvar_data, 0)? as usize;
    if i >= num_instructions {
        return Ok(None);
    }
    let table_start: usize = 2;
    let off_ptr = table_start
        .checked_add(i.checked_mul(2).ok_or(PrecompileError::SysvarTooShort)?)
        .ok_or(PrecompileError::SysvarTooShort)?;
    let ix_offset = read_u16_le(sysvar_data, off_ptr)? as usize;

    let accounts_count = read_u16_le(sysvar_data, ix_offset)? as usize;
    let accounts_size = accounts_count
        .checked_mul(ACCOUNT_META_LEN)
        .ok_or(PrecompileError::SysvarTooShort)?;
    let program_id_off = ix_offset
        .checked_add(2)
        .and_then(|x| x.checked_add(accounts_size))
        .ok_or(PrecompileError::SysvarTooShort)?;
    let program_id = read_slice(sysvar_data, program_id_off, PROGRAM_ID_LEN)?;
    let data_len_off = program_id_off + PROGRAM_ID_LEN;
    let data_len = read_u16_le(sysvar_data, data_len_off)? as usize;
    let data_off = data_len_off + 2;
    let data = read_slice(sysvar_data, data_off, data_len)?;
    Ok(Some((program_id, data)))
}

/// Verifies an Ed25519 precompile invocation in the same transaction signed
/// `(expected_pubkey, expected_message)`.
pub fn verify_ed25519(
    expected_pubkey: &[u8; ED25519_PUBKEY_LEN],
    expected_message: &[u8],
    sysvar_data: &[u8],
) -> Result<(), PrecompileError> {
    find_long_record(sysvar_data, &ED25519_PRECOMPILE_ID, ED25519_PUBKEY_LEN, |pk, msg| {
        pk == expected_pubkey.as_slice() && msg == expected_message
    })
}

/// Verifies a Secp256r1 precompile invocation in the same transaction signed
/// `(expected_pubkey_compressed, expected_message)`.
pub fn verify_secp256r1(
    expected_pubkey: &[u8; SECP256R1_PUBKEY_LEN],
    expected_message: &[u8],
    sysvar_data: &[u8],
) -> Result<(), PrecompileError> {
    find_long_record(sysvar_data, &SECP256R1_PRECOMPILE_ID, SECP256R1_PUBKEY_LEN, |pk, msg| {
        pk == expected_pubkey.as_slice() && msg == expected_message
    })
}

/// Verifies a Secp256k1 precompile invocation in the same transaction signed
/// `(expected_eth_address, expected_message)`. The eth_address is the standard
/// EVM-style 20-byte identifier (`keccak256(uncompressed_pubkey)[12..]`).
pub fn verify_secp256k1(
    expected_eth_address: &[u8; SECP256K1_ETH_ADDR_LEN],
    expected_message: &[u8],
    sysvar_data: &[u8],
) -> Result<(), PrecompileError> {
    find_short_record(sysvar_data, &SECP256K1_PRECOMPILE_ID, SECP256K1_ETH_ADDR_LEN, |addr, msg| {
        addr == expected_eth_address.as_slice() && msg == expected_message
    })
}

fn find_long_record<F>(
    sysvar_data: &[u8],
    expected_program_id: &Address,
    pubkey_len: usize,
    mut predicate: F,
) -> Result<(), PrecompileError>
where
    F: FnMut(&[u8], &[u8]) -> bool,
{
    if sysvar_data.len() < 2 {
        return Err(PrecompileError::SysvarTooShort);
    }
    let num_instructions = read_u16_le(sysvar_data, 0)? as usize;
    let prog_id_bytes = expected_program_id.as_array();

    for i in 0..num_instructions {
        let body = match read_ix_body(sysvar_data, i)? {
            Some(b) => b,
            None => continue,
        };
        let (program_id, data) = body;
        if program_id != prog_id_bytes.as_slice() {
            continue;
        }
        if data.len() < 2 {
            return Err(PrecompileError::InvalidLayout);
        }
        let num_records = data[0] as usize;
        let records_end = 2usize
            .checked_add(
                num_records
                    .checked_mul(LONG_OFFSETS_LEN)
                    .ok_or(PrecompileError::InvalidLayout)?,
            )
            .ok_or(PrecompileError::InvalidLayout)?;
        if records_end > data.len() {
            return Err(PrecompileError::InvalidLayout);
        }
        for r in 0..num_records {
            let rec_off = 2 + r * LONG_OFFSETS_LEN;
            let signature_offset = read_u16_le(data, rec_off)? as usize;
            let signature_ix_idx = read_u16_le(data, rec_off + 2)?;
            let public_key_offset = read_u16_le(data, rec_off + 4)? as usize;
            let public_key_ix_idx = read_u16_le(data, rec_off + 6)?;
            let message_data_offset = read_u16_le(data, rec_off + 8)? as usize;
            let message_data_size = read_u16_le(data, rec_off + 10)? as usize;
            let message_ix_idx = read_u16_le(data, rec_off + 12)?;

            if signature_ix_idx != LONG_SELF_INDEX
                || public_key_ix_idx != LONG_SELF_INDEX
                || message_ix_idx != LONG_SELF_INDEX
            {
                return Err(PrecompileError::CrossInstructionUnsupported);
            }
            let _signature = read_slice(data, signature_offset, ED25519_SIG_LEN)?;
            let public_key = read_slice(data, public_key_offset, pubkey_len)?;
            let message = read_slice(data, message_data_offset, message_data_size)?;
            if predicate(public_key, message) {
                return Ok(());
            }
        }
    }
    Err(PrecompileError::NoMatchingInvocation)
}

fn find_short_record<F>(
    sysvar_data: &[u8],
    expected_program_id: &Address,
    eth_addr_len: usize,
    mut predicate: F,
) -> Result<(), PrecompileError>
where
    F: FnMut(&[u8], &[u8]) -> bool,
{
    if sysvar_data.len() < 2 {
        return Err(PrecompileError::SysvarTooShort);
    }
    let num_instructions = read_u16_le(sysvar_data, 0)? as usize;
    let prog_id_bytes = expected_program_id.as_array();

    for i in 0..num_instructions {
        let body = match read_ix_body(sysvar_data, i)? {
            Some(b) => b,
            None => continue,
        };
        let (program_id, data) = body;
        if program_id != prog_id_bytes.as_slice() {
            continue;
        }
        if data.is_empty() {
            return Err(PrecompileError::InvalidLayout);
        }
        let num_records = data[0] as usize;
        let records_end = 1usize
            .checked_add(
                num_records
                    .checked_mul(SHORT_OFFSETS_LEN)
                    .ok_or(PrecompileError::InvalidLayout)?,
            )
            .ok_or(PrecompileError::InvalidLayout)?;
        if records_end > data.len() {
            return Err(PrecompileError::InvalidLayout);
        }
        for r in 0..num_records {
            let rec_off = 1 + r * SHORT_OFFSETS_LEN;
            let signature_offset = read_u16_le(data, rec_off)? as usize;
            let signature_ix_idx = read_u8(data, rec_off + 2)?;
            let eth_address_offset = read_u16_le(data, rec_off + 3)? as usize;
            let eth_address_ix_idx = read_u8(data, rec_off + 5)?;
            let message_data_offset = read_u16_le(data, rec_off + 6)? as usize;
            let message_data_size = read_u16_le(data, rec_off + 8)? as usize;
            let message_ix_idx = read_u8(data, rec_off + 10)?;

            if signature_ix_idx != SHORT_SELF_INDEX
                || eth_address_ix_idx != SHORT_SELF_INDEX
                || message_ix_idx != SHORT_SELF_INDEX
            {
                return Err(PrecompileError::CrossInstructionUnsupported);
            }
            let _signature = read_slice(data, signature_offset, SECP256K1_SIG_LEN + SECP256K1_RECID_LEN)?;
            let eth_address = read_slice(data, eth_address_offset, eth_addr_len)?;
            let message = read_slice(data, message_data_offset, message_data_size)?;
            if predicate(eth_address, message) {
                return Ok(());
            }
        }
    }
    Err(PrecompileError::NoMatchingInvocation)
}
