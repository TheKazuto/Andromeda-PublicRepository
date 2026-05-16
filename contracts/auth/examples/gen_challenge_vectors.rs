//! Golden-vector generator — host-only, `host-test` feature required.
//!
//! Run from the repo root with:
//!
//! ```bash
//! cargo run -p andromeda_auth --features host-test --example gen_challenge_vectors > fixtures/clear_signing_vectors.json
//! ```
//!
//! The output is the source of truth: TS (`ika-backend`) and Go (`gateway`)
//! must reproduce every `hashHex` byte-for-byte. CI fails on divergence.
//!
//! Coverage:
//!   * Phase 1 — rules-policy (17 ops + init + initAuthorityHashFromSlot = 19)
//!   * Phase 2 — 7 policies admin (23 ops)
//!
//! Inputs are deterministic — every byte is derived from a small seed so
//! the file regenerates byte-identical across machines.

use andromeda_auth::challenge as rp;
use andromeda_auth::hash::hashv;
use andromeda_auth::human_message::{self as hm, MAX_HUMAN_MESSAGE_BYTES};
use serde::Serialize;
use solana_address::Address;
use std::collections::BTreeMap;

// ── Output schema ────────────────────────────────────────────────

#[derive(Serialize)]
struct Output {
    /// Stable on-disk version of this file.
    version: u32,
    /// `andromeda::*::v2` clear-signing wire format.
    wire_version: &'static str,
    vectors: BTreeMap<String, Vector>,
}

#[derive(Serialize)]
struct Vector {
    inputs: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    human_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    human_len_le_hex: Option<String>,
    hash_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    clear_signing_version: Option<&'static str>,
}

const RP_CLEAR_VERSION: &str = "rules-policy-clear-v1";
const POLICY_CLEAR_VERSION: &str = "policy-clear-v1";

// ── Deterministic fixture builders ───────────────────────────────

fn seed_bytes(label: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| label.wrapping_add(i as u8)).collect()
}

fn seed_addr(label: u8) -> [u8; 32] {
    let v = seed_bytes(label, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn seed_32(label: u8) -> [u8; 32] {
    seed_addr(label)
}

fn seed_member_slot(scheme: u8, id_byte: u8) -> [u8; 34] {
    let mut s = [0u8; 34];
    s[0] = scheme;
    let id_len = match scheme {
        0 | 4 => 32,
        1 => 20,
        2 | 3 => 33,
        _ => 32,
    };
    for i in 0..id_len {
        s[1 + i] = id_byte.wrapping_add(i as u8);
    }
    s
}

fn hex_lower(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 2);
    for x in b {
        out.push_str(&format!("{:02x}", x));
    }
    out
}

fn human_len_le_hex(len: usize) -> String {
    let lo = (len & 0xff) as u8;
    let hi = ((len >> 8) & 0xff) as u8;
    format!("{:02x}{:02x}", lo, hi)
}

fn rendered(f: impl FnOnce(&mut [u8; MAX_HUMAN_MESSAGE_BYTES]) -> usize) -> (String, String) {
    let mut buf = [0u8; MAX_HUMAN_MESSAGE_BYTES];
    let len = f(&mut buf);
    let msg = core::str::from_utf8(&buf[..len])
        .expect("ASCII")
        .to_string();
    (msg, human_len_le_hex(len))
}

// ── Phase 1 — rules-policy (19 vectors) ──────────────────────────

fn vec_rules_policy_init() -> (String, Vector) {
    let dwallet = seed_addr(0x01);
    let init_authority_slot = seed_member_slot(0, 0x02);
    let primary_slot = seed_member_slot(1, 0x03);
    let quorum_threshold = 3u8;
    let daily_limit_some = 1u8;
    let daily_limit = 1_000_000u64;
    let cooldown_seconds = 86_400u64;
    let allowed_destinations_some = 1u8;
    let hash = rp::rules_policy_init_challenge(
        &Address::from(dwallet),
        &init_authority_slot,
        &primary_slot,
        quorum_threshold,
        daily_limit_some,
        daily_limit,
        cooldown_seconds,
        allowed_destinations_some,
    );
    (
        "rules_policy_init".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "initAuthoritySlot": hex_lower(&init_authority_slot),
                "primarySlot": hex_lower(&primary_slot),
                "quorumThreshold": quorum_threshold,
                "dailyLimitSome": daily_limit_some == 1,
                "dailyLimit": daily_limit.to_string(),
                "cooldownSeconds": cooldown_seconds.to_string(),
                "allowedDestinationsSome": allowed_destinations_some == 1,
            }),
            human_message: None,
            human_len_le_hex: None,
            hash_hex: hex_lower(&hash),
            clear_signing_version: None,
        },
    )
}

fn vec_init_authority_hash_from_slot() -> (String, Vector) {
    let slot = seed_member_slot(0, 0x10);
    let hash = hashv(&[&slot]);
    (
        "init_authority_hash_from_slot".into(),
        Vector {
            inputs: serde_json::json!({ "slot": hex_lower(&slot) }),
            human_message: None,
            human_len_le_hex: None,
            hash_hex: hex_lower(&hash),
            clear_signing_version: None,
        },
    )
}

fn vec_primary_recover() -> (String, Vector) {
    let dwallet = seed_addr(0x11);
    let message_approval = seed_addr(0x12);
    let message_digest = seed_32(0x13);
    let metadata_digest = seed_32(0x14);
    let user_pubkey = seed_32(0x15);
    let signature_scheme = 5u16;
    let message_approval_bump = 254u8;
    let nonce = 42u64;
    let primary_slot = seed_member_slot(1, 0x16);

    let (human, hlen_hex) = rendered(|buf| {
        hm::primary_recover_message(
            buf,
            &Address::from(dwallet),
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
        )
        .unwrap()
    });
    let hash = rp::primary_recover_challenge(
        &Address::from(dwallet),
        &Address::from(message_approval),
        &message_digest,
        &metadata_digest,
        &user_pubkey,
        signature_scheme,
        message_approval_bump,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "primary_recover".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "messageApproval": hex_lower(&message_approval),
                "messageDigest": hex_lower(&message_digest),
                "metadataDigest": hex_lower(&metadata_digest),
                "userPubkey": hex_lower(&user_pubkey),
                "signatureScheme": signature_scheme,
                "messageApprovalBump": message_approval_bump,
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_quorum_session_open() -> (String, Vector) {
    let dwallet = seed_addr(0x21);
    let message_digest = seed_32(0x22);
    let metadata_digest = seed_32(0x23);
    let user_pubkey = seed_32(0x24);
    let signature_scheme = 0u16;
    let message_approval_bump = 250u8;
    let amount = 5_000_000_000u64;
    let destination = seed_32(0x25);
    let expires_at = 1_900_000_000i64;
    let session_nonce = 7u64;
    let primary_slot = seed_member_slot(1, 0x26);

    let (human, hlen_hex) = rendered(|buf| {
        hm::quorum_session_open_message(
            buf,
            &Address::from(dwallet),
            amount,
            &destination,
            &message_digest,
            &metadata_digest,
            signature_scheme,
            expires_at,
        )
        .unwrap()
    });
    let hash = rp::quorum_session_open_challenge(
        &Address::from(dwallet),
        &message_digest,
        &metadata_digest,
        &user_pubkey,
        signature_scheme,
        message_approval_bump,
        amount,
        &destination,
        expires_at,
        session_nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "quorum_session_open".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "messageDigest": hex_lower(&message_digest),
                "metadataDigest": hex_lower(&metadata_digest),
                "userPubkey": hex_lower(&user_pubkey),
                "signatureScheme": signature_scheme,
                "messageApprovalBump": message_approval_bump,
                "amount": amount.to_string(),
                "destination": hex_lower(&destination),
                "expiresAt": expires_at.to_string(),
                "sessionNonce": session_nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_quorum_contribute() -> (String, Vector) {
    let session = seed_addr(0x31);
    let member_slot = seed_member_slot(0, 0x32);
    let dwallet = seed_addr(0x33);
    let amount = 2_500_000_000u64;
    let destination = seed_32(0x34);
    let message_digest = seed_32(0x35);
    let metadata_digest = seed_32(0x36);
    let user_pubkey = seed_32(0x37);
    let signature_scheme = 0u16;
    let message_approval_bump = 250u8;
    let expires_at = 1_900_000_000i64;

    let (human, hlen_hex) = rendered(|buf| {
        hm::quorum_contribute_message(
            buf,
            &Address::from(session),
            &member_slot,
            &Address::from(dwallet),
            amount,
            &destination,
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
            expires_at,
        )
        .unwrap()
    });
    let hash = rp::quorum_contribute_challenge(
        &Address::from(session),
        &member_slot,
        &Address::from(dwallet),
        amount,
        &destination,
        &message_digest,
        &metadata_digest,
        &user_pubkey,
        signature_scheme,
        message_approval_bump,
        expires_at,
    )
    .unwrap();
    (
        "quorum_contribute".into(),
        Vector {
            inputs: serde_json::json!({
                "session": hex_lower(&session),
                "memberSlot": hex_lower(&member_slot),
                "dwallet": hex_lower(&dwallet),
                "amount": amount.to_string(),
                "destination": hex_lower(&destination),
                "messageDigest": hex_lower(&message_digest),
                "metadataDigest": hex_lower(&metadata_digest),
                "userPubkey": hex_lower(&user_pubkey),
                "signatureScheme": signature_scheme,
                "messageApprovalBump": message_approval_bump,
                "expiresAt": expires_at.to_string(),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

// ── Admin (12 ops) ───────────────────────────────────────────────

fn vec_admin_add_member() -> (String, Vector) {
    let dwallet = seed_addr(0x41);
    let policy = seed_addr(0x42);
    let new_member_slot = seed_member_slot(0, 0x43);
    let nonce = 11u64;
    let primary_slot = seed_member_slot(1, 0x44);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_add_member_message(
            buf,
            &new_member_slot,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_add_member_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        &new_member_slot,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_add_member".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newMemberSlot": hex_lower(&new_member_slot),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_remove_member() -> (String, Vector) {
    let dwallet = seed_addr(0x45);
    let policy = seed_addr(0x46);
    let member_slot_to_remove = seed_member_slot(2, 0x47);
    let nonce = 12u64;
    let primary_slot = seed_member_slot(1, 0x48);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_remove_member_message(
            buf,
            &member_slot_to_remove,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_remove_member_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        &member_slot_to_remove,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_remove_member".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "memberSlotToRemove": hex_lower(&member_slot_to_remove),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_add_destination() -> (String, Vector) {
    let dwallet = seed_addr(0x49);
    let policy = seed_addr(0x4a);
    let destination = seed_32(0x4b);
    let nonce = 13u64;
    let primary_slot = seed_member_slot(1, 0x4c);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_add_destination_message(
            buf,
            &destination,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_add_destination_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        &destination,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_add_destination".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "destination": hex_lower(&destination),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_remove_destination() -> (String, Vector) {
    let dwallet = seed_addr(0x4d);
    let policy = seed_addr(0x4e);
    let destination = seed_32(0x4f);
    let nonce = 14u64;
    let primary_slot = seed_member_slot(1, 0x50);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_remove_destination_message(
            buf,
            &destination,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_remove_destination_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        &destination,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_remove_destination".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "destination": hex_lower(&destination),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_revoke() -> (String, Vector) {
    let dwallet = seed_addr(0x51);
    let policy = seed_addr(0x52);
    let nonce = 15u64;
    let primary_slot = seed_member_slot(1, 0x53);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_revoke_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = rp::admin_revoke_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_revoke".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_set_primary() -> (String, Vector) {
    let dwallet = seed_addr(0x54);
    let policy = seed_addr(0x55);
    let new_primary_slot = seed_member_slot(0, 0x56);
    let nonce = 16u64;
    let current_primary_slot = seed_member_slot(1, 0x57);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_set_primary_message(
            buf,
            &new_primary_slot,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_set_primary_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        &new_primary_slot,
        nonce,
        &current_primary_slot,
    )
    .unwrap();
    (
        "admin_set_primary".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newPrimarySlot": hex_lower(&new_primary_slot),
                "nonce": nonce.to_string(),
                "currentPrimarySlot": hex_lower(&current_primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_set_qt_immediate() -> (String, Vector) {
    let dwallet = seed_addr(0x58);
    let policy = seed_addr(0x59);
    let new_threshold = 5u8;
    let nonce = 17u64;
    let primary_slot = seed_member_slot(1, 0x5a);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_set_quorum_threshold_immediate_message(
            buf,
            new_threshold,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_set_quorum_threshold_immediate_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        new_threshold,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_set_quorum_threshold_immediate".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newThreshold": new_threshold,
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_set_dl_immediate() -> (String, Vector) {
    let dwallet = seed_addr(0x5b);
    let policy = seed_addr(0x5c);
    let new_some = 1u8;
    let new_limit = 2_000_000u64;
    let nonce = 18u64;
    let primary_slot = seed_member_slot(1, 0x5d);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_set_daily_limit_immediate_message(
            buf,
            new_some,
            new_limit,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_set_daily_limit_immediate_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        new_some,
        new_limit,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_set_daily_limit_immediate".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newSome": new_some == 1,
                "newLimit": new_limit.to_string(),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_set_cd_immediate() -> (String, Vector) {
    let dwallet = seed_addr(0x5e);
    let policy = seed_addr(0x5f);
    let new_cooldown_seconds = 43_200u64;
    let nonce = 19u64;
    let primary_slot = seed_member_slot(1, 0x60);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_set_cooldown_immediate_message(
            buf,
            new_cooldown_seconds,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_set_cooldown_immediate_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        new_cooldown_seconds,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_set_cooldown_immediate".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newCooldownSeconds": new_cooldown_seconds.to_string(),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_propose_qt() -> (String, Vector) {
    let dwallet = seed_addr(0x61);
    let policy = seed_addr(0x62);
    let new_threshold = 4u8;
    let nonce = 20u64;
    let primary_slot = seed_member_slot(1, 0x63);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_propose_quorum_threshold_message(
            buf,
            new_threshold,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_propose_quorum_threshold_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        new_threshold,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_propose_quorum_threshold".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newThreshold": new_threshold,
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_propose_dl() -> (String, Vector) {
    let dwallet = seed_addr(0x64);
    let policy = seed_addr(0x65);
    let new_some = 0u8;
    let new_limit = 0u64;
    let nonce = 21u64;
    let primary_slot = seed_member_slot(1, 0x66);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_propose_daily_limit_message(
            buf,
            new_some,
            new_limit,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_propose_daily_limit_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        new_some,
        new_limit,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_propose_daily_limit".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newSome": new_some == 1,
                "newLimit": new_limit.to_string(),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_admin_propose_cd() -> (String, Vector) {
    let dwallet = seed_addr(0x67);
    let policy = seed_addr(0x68);
    let new_cooldown_seconds = 7_200u64;
    let nonce = 22u64;
    let primary_slot = seed_member_slot(1, 0x69);
    let (human, hlen_hex) = rendered(|buf| {
        hm::admin_propose_cooldown_message(
            buf,
            new_cooldown_seconds,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = rp::admin_propose_cooldown_challenge(
        &Address::from(dwallet),
        &Address::from(policy),
        new_cooldown_seconds,
        nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "admin_propose_cooldown".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newCooldownSeconds": new_cooldown_seconds.to_string(),
                "nonce": nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

// ── OIDC (2) ─────────────────────────────────────────────────────

fn vec_oidc_session_open() -> (String, Vector) {
    let dwallet = seed_addr(0x71);
    let primary_slot = {
        let mut s = [0u8; 34];
        s[0] = 4; // OIDC
        let id = seed_32(0x72);
        s[1..33].copy_from_slice(&id);
        s
    };
    let eph_pk = seed_32(0x73);
    let not_after_unix_ts = 1_900_000_000u64;
    let jwt_digest = seed_32(0x74);
    let jwk_registry = seed_32(0x75);
    let oidc_verifier_version = 1u32;
    let session_nonce = 31u64;
    let (human, hlen_hex) = rendered(|buf| {
        hm::oidc_session_open_message(buf, &Address::from(dwallet), not_after_unix_ts, &eph_pk)
            .unwrap()
    });
    let hash = rp::oidc_session_open_challenge(
        &Address::from(dwallet),
        &primary_slot,
        &eph_pk,
        not_after_unix_ts,
        &jwt_digest,
        &Address::from(jwk_registry),
        oidc_verifier_version,
        session_nonce,
    )
    .unwrap();
    (
        "oidc_session_open".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "primarySlot": hex_lower(&primary_slot),
                "ephPk": hex_lower(&eph_pk),
                "notAfterUnixTs": not_after_unix_ts.to_string(),
                "jwtDigest": hex_lower(&jwt_digest),
                "jwkRegistry": hex_lower(&jwk_registry),
                "oidcVerifierVersion": oidc_verifier_version,
                "sessionNonce": session_nonce.to_string(),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

fn vec_oidc_primary_use() -> (String, Vector) {
    let session = seed_addr(0x81);
    let dwallet = seed_addr(0x82);
    let message_approval = seed_addr(0x83);
    let message_digest = seed_32(0x84);
    let metadata_digest = seed_32(0x85);
    let user_pubkey = seed_32(0x86);
    let signature_scheme = 0u16;
    let message_approval_bump = 252u8;
    let use_nonce = 41u64;
    let primary_slot = {
        let mut s = [0u8; 34];
        s[0] = 4;
        let id = seed_32(0x87);
        s[1..33].copy_from_slice(&id);
        s
    };
    let (human, hlen_hex) = rendered(|buf| {
        hm::oidc_primary_use_message(
            buf,
            &Address::from(session),
            &Address::from(dwallet),
            &message_digest,
            &metadata_digest,
            &user_pubkey,
            signature_scheme,
        )
        .unwrap()
    });
    let hash = rp::oidc_primary_use_challenge(
        &Address::from(session),
        &Address::from(dwallet),
        &Address::from(message_approval),
        &message_digest,
        &metadata_digest,
        &user_pubkey,
        signature_scheme,
        message_approval_bump,
        use_nonce,
        &primary_slot,
    )
    .unwrap();
    (
        "oidc_primary_use".into(),
        Vector {
            inputs: serde_json::json!({
                "session": hex_lower(&session),
                "dwallet": hex_lower(&dwallet),
                "messageApproval": hex_lower(&message_approval),
                "messageDigest": hex_lower(&message_digest),
                "metadataDigest": hex_lower(&metadata_digest),
                "userPubkey": hex_lower(&user_pubkey),
                "signatureScheme": signature_scheme,
                "messageApprovalBump": message_approval_bump,
                "useNonce": use_nonce.to_string(),
                "primarySlot": hex_lower(&primary_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(RP_CLEAR_VERSION),
        },
    )
}

// ── Phase 2 — 7 policies (23 ops) ────────────────────────────────
//
// Hash construction mirrors `admin_hash_with_human` in each policy crate:
//
//   sha256(
//     DOMAIN || op_tag
//     || human_len_u16_le || human_bytes
//     || dwallet || policy || nonce_le || owner_slot
//     || extras...
//   )

fn admin_hash(
    domain: &[u8],
    op_tag: &[u8],
    human: &[u8],
    dwallet: &[u8; 32],
    policy: &[u8; 32],
    nonce: u64,
    owner_slot: &[u8; 34],
    extras: &[&[u8]],
) -> [u8; 32] {
    let h_len = (human.len() as u16).to_le_bytes();
    let nonce_le = nonce.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(8 + extras.len());
    parts.push(domain);
    parts.push(op_tag);
    parts.push(&h_len);
    parts.push(human);
    parts.push(dwallet);
    parts.push(policy);
    parts.push(&nonce_le);
    parts.push(owner_slot);
    parts.extend_from_slice(extras);
    hashv(&parts)
}

// allowlist-destinations (4)
const DOMAIN_ALLOWLIST_V2: &[u8] = b"andromeda::allowlist-destinations::v2";

fn vec_allowlist_add_destination() -> (String, Vector) {
    let dwallet = seed_addr(0x91);
    let policy = seed_addr(0x92);
    let destination = seed_32(0x93);
    let nonce = 51u64;
    let owner_slot = seed_member_slot(1, 0x94);
    let (human, hlen_hex) = rendered(|buf| {
        hm::allowlist_add_destination_message(
            buf,
            &destination,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_ALLOWLIST_V2,
        b"add-destination",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&destination],
    );
    (
        "allowlist_add_destination".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "destination": hex_lower(&destination),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_allowlist_remove_destination() -> (String, Vector) {
    let dwallet = seed_addr(0x95);
    let policy = seed_addr(0x96);
    let destination = seed_32(0x97);
    let nonce = 52u64;
    let owner_slot = seed_member_slot(1, 0x98);
    let (human, hlen_hex) = rendered(|buf| {
        hm::allowlist_remove_destination_message(
            buf,
            &destination,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_ALLOWLIST_V2,
        b"remove-destination",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&destination],
    );
    (
        "allowlist_remove_destination".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "destination": hex_lower(&destination),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_allowlist_pause() -> (String, Vector) {
    let dwallet = seed_addr(0x99);
    let policy = seed_addr(0x9a);
    let nonce = 53u64;
    let owner_slot = seed_member_slot(1, 0x9b);
    let (human, hlen_hex) = rendered(|buf| {
        hm::allowlist_pause_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_ALLOWLIST_V2,
        b"pause",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "allowlist_pause".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_allowlist_resume() -> (String, Vector) {
    let dwallet = seed_addr(0x9c);
    let policy = seed_addr(0x9d);
    let nonce = 54u64;
    let owner_slot = seed_member_slot(1, 0x9e);
    let (human, hlen_hex) = rendered(|buf| {
        hm::allowlist_resume_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_ALLOWLIST_V2,
        b"resume",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "allowlist_resume".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

// velocity-guard (3)
const DOMAIN_VELOCITY_V2: &[u8] = b"andromeda::velocity-guard::v2";

fn vec_velocity_update_window() -> (String, Vector) {
    let dwallet = seed_addr(0xa1);
    let policy = seed_addr(0xa2);
    let max_sigs_per_window = 10u32;
    let window_slots = 256u64;
    let nonce = 61u64;
    let owner_slot = seed_member_slot(1, 0xa3);
    let (human, hlen_hex) = rendered(|buf| {
        hm::velocity_update_window_message(
            buf,
            max_sigs_per_window,
            window_slots,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let max_le = max_sigs_per_window.to_le_bytes();
    let win_le = window_slots.to_le_bytes();
    let hash = admin_hash(
        DOMAIN_VELOCITY_V2,
        b"update-window",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&max_le, &win_le],
    );
    (
        "velocity_update_window".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "maxSigsPerWindow": max_sigs_per_window,
                "windowSlots": window_slots.to_string(),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_velocity_pause() -> (String, Vector) {
    let dwallet = seed_addr(0xa4);
    let policy = seed_addr(0xa5);
    let nonce = 62u64;
    let owner_slot = seed_member_slot(1, 0xa6);
    let (human, hlen_hex) = rendered(|buf| {
        hm::velocity_pause_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_VELOCITY_V2,
        b"pause",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "velocity_pause".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_velocity_resume() -> (String, Vector) {
    let dwallet = seed_addr(0xa7);
    let policy = seed_addr(0xa8);
    let nonce = 63u64;
    let owner_slot = seed_member_slot(1, 0xa9);
    let (human, hlen_hex) = rendered(|buf| {
        hm::velocity_resume_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_VELOCITY_V2,
        b"resume",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "velocity_resume".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

// time-lock (3)
const DOMAIN_TIMELOCK_V2: &[u8] = b"andromeda::time-lock::v2";

fn vec_time_lock_update_window() -> (String, Vector) {
    let dwallet = seed_addr(0xb1);
    let policy = seed_addr(0xb2);
    let mode = 2u8; // between
    let start_slot = 100u64;
    let end_slot = 200u64;
    let recurring_period_slots = 0u64;
    let nonce = 71u64;
    let owner_slot = seed_member_slot(1, 0xb3);
    let (human, hlen_hex) = rendered(|buf| {
        hm::time_lock_update_window_message(
            buf,
            mode,
            start_slot,
            end_slot,
            recurring_period_slots,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let mode_b = [mode];
    let start_le = start_slot.to_le_bytes();
    let end_le = end_slot.to_le_bytes();
    let period_le = recurring_period_slots.to_le_bytes();
    let hash = admin_hash(
        DOMAIN_TIMELOCK_V2,
        b"update-window",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&mode_b, &start_le, &end_le, &period_le],
    );
    (
        "time_lock_update_window".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "mode": mode,
                "startSlot": start_slot.to_string(),
                "endSlot": end_slot.to_string(),
                "recurringPeriodSlots": recurring_period_slots.to_string(),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_time_lock_pause() -> (String, Vector) {
    let dwallet = seed_addr(0xb4);
    let policy = seed_addr(0xb5);
    let nonce = 72u64;
    let owner_slot = seed_member_slot(1, 0xb6);
    let (human, hlen_hex) = rendered(|buf| {
        hm::time_lock_pause_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_TIMELOCK_V2,
        b"pause",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "time_lock_pause".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_time_lock_resume() -> (String, Vector) {
    let dwallet = seed_addr(0xb7);
    let policy = seed_addr(0xb8);
    let nonce = 73u64;
    let owner_slot = seed_member_slot(1, 0xb9);
    let (human, hlen_hex) = rendered(|buf| {
        hm::time_lock_resume_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_TIMELOCK_V2,
        b"resume",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "time_lock_resume".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

// oracle-conditional (3)
const DOMAIN_ORACLE_V2: &[u8] = b"andromeda::oracle-conditional::v2";

fn vec_oracle_update_bounds() -> (String, Vector) {
    let dwallet = seed_addr(0xc1);
    let policy = seed_addr(0xc2);
    let min_price = 1_000_000i64;
    let max_price = 5_000_000i64;
    let max_age_slots = 32u64;
    let max_confidence_bps = 250u16;
    let nonce = 81u64;
    let owner_slot = seed_member_slot(1, 0xc3);
    let (human, hlen_hex) = rendered(|buf| {
        hm::oracle_update_bounds_message(
            buf,
            min_price,
            max_price,
            max_age_slots,
            max_confidence_bps,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let min_le = min_price.to_le_bytes();
    let max_le = max_price.to_le_bytes();
    let age_le = max_age_slots.to_le_bytes();
    let bps_le = max_confidence_bps.to_le_bytes();
    let hash = admin_hash(
        DOMAIN_ORACLE_V2,
        b"update-bounds",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&min_le, &max_le, &age_le, &bps_le],
    );
    (
        "oracle_update_bounds".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "minPrice": min_price.to_string(),
                "maxPrice": max_price.to_string(),
                "maxAgeSlots": max_age_slots.to_string(),
                "maxConfidenceBps": max_confidence_bps,
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_oracle_pause() -> (String, Vector) {
    let dwallet = seed_addr(0xc4);
    let policy = seed_addr(0xc5);
    let nonce = 82u64;
    let owner_slot = seed_member_slot(1, 0xc6);
    let (human, hlen_hex) = rendered(|buf| {
        hm::oracle_pause_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_ORACLE_V2,
        b"pause",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "oracle_pause".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_oracle_resume() -> (String, Vector) {
    let dwallet = seed_addr(0xc7);
    let policy = seed_addr(0xc8);
    let nonce = 83u64;
    let owner_slot = seed_member_slot(1, 0xc9);
    let (human, hlen_hex) = rendered(|buf| {
        hm::oracle_resume_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_ORACLE_V2,
        b"resume",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "oracle_resume".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

// passkey-step-up (3)
const DOMAIN_PASSKEY_V2: &[u8] = b"andromeda::passkey-step-up::v2";

fn vec_passkey_update_policy() -> (String, Vector) {
    let dwallet = seed_addr(0xd1);
    let policy = seed_addr(0xd2);
    let threshold_amount = 100_000_000u64;
    let passkey_pubkey: [u8; 33] = {
        let v = seed_bytes(0xd3, 33);
        let mut a = [0u8; 33];
        a.copy_from_slice(&v);
        a
    };
    let nonce = 91u64;
    let owner_slot = seed_member_slot(1, 0xd4);
    let (human, hlen_hex) = rendered(|buf| {
        hm::passkey_update_policy_message(
            buf,
            threshold_amount,
            &passkey_pubkey,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let amount_le = threshold_amount.to_le_bytes();
    let hash = admin_hash(
        DOMAIN_PASSKEY_V2,
        b"update-policy",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&amount_le, &passkey_pubkey],
    );
    (
        "passkey_update_policy".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "thresholdAmount": threshold_amount.to_string(),
                "passkeyPubkey": hex_lower(&passkey_pubkey),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_passkey_pause() -> (String, Vector) {
    let dwallet = seed_addr(0xd5);
    let policy = seed_addr(0xd6);
    let nonce = 92u64;
    let owner_slot = seed_member_slot(1, 0xd7);
    let (human, hlen_hex) = rendered(|buf| {
        hm::passkey_pause_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_PASSKEY_V2,
        b"pause",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "passkey_pause".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_passkey_resume() -> (String, Vector) {
    let dwallet = seed_addr(0xd8);
    let policy = seed_addr(0xd9);
    let nonce = 93u64;
    let owner_slot = seed_member_slot(1, 0xda);
    let (human, hlen_hex) = rendered(|buf| {
        hm::passkey_resume_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_PASSKEY_V2,
        b"resume",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "passkey_resume".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

// session-keys (4)
const DOMAIN_SESSION_KEYS_V2: &[u8] = b"andromeda::session-keys::v2";

fn vec_session_keys_revoke() -> (String, Vector) {
    let dwallet = seed_addr(0xe1);
    let policy = seed_addr(0xe2);
    let nonce = 101u64;
    let owner_slot = seed_member_slot(1, 0xe3);
    let (human, hlen_hex) = rendered(|buf| {
        hm::session_keys_revoke_session_message(
            buf,
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_SESSION_KEYS_V2,
        b"revoke-session",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "session_keys_revoke_session".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_session_keys_add_program() -> (String, Vector) {
    let dwallet = seed_addr(0xe4);
    let policy = seed_addr(0xe5);
    let program_id = seed_addr(0xe6);
    let nonce = 102u64;
    let owner_slot = seed_member_slot(1, 0xe7);
    let (human, hlen_hex) = rendered(|buf| {
        hm::session_keys_add_allowed_program_message(
            buf,
            &Address::from(program_id),
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_SESSION_KEYS_V2,
        b"add-allowed-program",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&program_id],
    );
    (
        "session_keys_add_allowed_program".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "programId": hex_lower(&program_id),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_session_keys_remove_program() -> (String, Vector) {
    let dwallet = seed_addr(0xe8);
    let policy = seed_addr(0xe9);
    let program_id = seed_addr(0xea);
    let nonce = 103u64;
    let owner_slot = seed_member_slot(1, 0xeb);
    let (human, hlen_hex) = rendered(|buf| {
        hm::session_keys_remove_allowed_program_message(
            buf,
            &Address::from(program_id),
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_SESSION_KEYS_V2,
        b"remove-allowed-program",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&program_id],
    );
    (
        "session_keys_remove_allowed_program".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "programId": hex_lower(&program_id),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_session_keys_close() -> (String, Vector) {
    let dwallet = seed_addr(0xec);
    let policy = seed_addr(0xed);
    let recipient = seed_addr(0xee);
    let nonce = 104u64;
    let owner_slot = seed_member_slot(1, 0xef);
    let (human, hlen_hex) = rendered(|buf| {
        hm::session_keys_close_session_message(
            buf,
            &Address::from(recipient),
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_SESSION_KEYS_V2,
        b"close-session",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&recipient],
    );
    (
        "session_keys_close_session".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "recipient": hex_lower(&recipient),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

// fhe-gated (3)
const DOMAIN_FHE_V2: &[u8] = b"andromeda::fhe-gated::v2";

fn vec_fhe_rotate_authority() -> (String, Vector) {
    let dwallet = seed_addr(0xf1);
    let policy = seed_addr(0xf2);
    let new_fhe_authority = seed_addr(0xf3);
    let nonce = 111u64;
    let owner_slot = seed_member_slot(1, 0xf4);
    let (human, hlen_hex) = rendered(|buf| {
        hm::fhe_rotate_authority_message(
            buf,
            &Address::from(new_fhe_authority),
            &Address::from(policy),
            &Address::from(dwallet),
        )
        .unwrap()
    });
    let hash = admin_hash(
        DOMAIN_FHE_V2,
        b"rotate-authority",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[&new_fhe_authority],
    );
    (
        "fhe_rotate_authority".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "newFheAuthority": hex_lower(&new_fhe_authority),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_fhe_pause() -> (String, Vector) {
    let dwallet = seed_addr(0xf5);
    let policy = seed_addr(0xf6);
    let nonce = 112u64;
    let owner_slot = seed_member_slot(1, 0xf7);
    let (human, hlen_hex) = rendered(|buf| {
        hm::fhe_pause_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_FHE_V2,
        b"pause",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "fhe_pause".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn vec_fhe_resume() -> (String, Vector) {
    let dwallet = seed_addr(0xf8);
    let policy = seed_addr(0xf9);
    let nonce = 113u64;
    let owner_slot = seed_member_slot(1, 0xfa);
    let (human, hlen_hex) = rendered(|buf| {
        hm::fhe_resume_message(buf, &Address::from(policy), &Address::from(dwallet)).unwrap()
    });
    let hash = admin_hash(
        DOMAIN_FHE_V2,
        b"resume",
        human.as_bytes(),
        &dwallet,
        &policy,
        nonce,
        &owner_slot,
        &[],
    );
    (
        "fhe_resume".into(),
        Vector {
            inputs: serde_json::json!({
                "dwallet": hex_lower(&dwallet),
                "policy": hex_lower(&policy),
                "nonce": nonce.to_string(),
                "ownerSlot": hex_lower(&owner_slot),
            }),
            human_message: Some(human),
            human_len_le_hex: Some(hlen_hex),
            hash_hex: hex_lower(&hash),
            clear_signing_version: Some(POLICY_CLEAR_VERSION),
        },
    )
}

fn main() {
    let pairs: Vec<(String, Vector)> = vec![
        vec_rules_policy_init(),
        vec_init_authority_hash_from_slot(),
        vec_primary_recover(),
        vec_quorum_session_open(),
        vec_quorum_contribute(),
        vec_admin_add_member(),
        vec_admin_remove_member(),
        vec_admin_add_destination(),
        vec_admin_remove_destination(),
        vec_admin_revoke(),
        vec_admin_set_primary(),
        vec_admin_set_qt_immediate(),
        vec_admin_set_dl_immediate(),
        vec_admin_set_cd_immediate(),
        vec_admin_propose_qt(),
        vec_admin_propose_dl(),
        vec_admin_propose_cd(),
        vec_oidc_session_open(),
        vec_oidc_primary_use(),
        vec_allowlist_add_destination(),
        vec_allowlist_remove_destination(),
        vec_allowlist_pause(),
        vec_allowlist_resume(),
        vec_velocity_update_window(),
        vec_velocity_pause(),
        vec_velocity_resume(),
        vec_time_lock_update_window(),
        vec_time_lock_pause(),
        vec_time_lock_resume(),
        vec_oracle_update_bounds(),
        vec_oracle_pause(),
        vec_oracle_resume(),
        vec_passkey_update_policy(),
        vec_passkey_pause(),
        vec_passkey_resume(),
        vec_session_keys_revoke(),
        vec_session_keys_add_program(),
        vec_session_keys_remove_program(),
        vec_session_keys_close(),
        vec_fhe_rotate_authority(),
        vec_fhe_pause(),
        vec_fhe_resume(),
    ];
    let mut vectors = BTreeMap::new();
    for (k, v) in pairs {
        if vectors.insert(k.clone(), v).is_some() {
            panic!("duplicate vector key: {}", k);
        }
    }
    let out = Output {
        version: 2,
        wire_version: "clear-signing-v2",
        vectors,
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
