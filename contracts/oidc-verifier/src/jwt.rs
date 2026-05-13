//! JWT structural parsing: split `header.payload.signature`, strict base64url
//! decoding, and the base64url-no-pad encoder used to recompute `oidc_nonce`.

use crate::OidcVerifyError;

/// The three base64url segments of a compact JWS, plus the JWS signing input
/// (`header_b64 || "." || payload_b64`, the ASCII bytes the provider signed).
pub struct Segments<'a> {
    pub header_b64: &'a [u8],
    pub payload_b64: &'a [u8],
    pub sig_b64: &'a [u8],
    pub signing_input: &'a [u8],
}

/// Splits `jwt` on its two `.` separators. Requires exactly two dots, all three
/// segments non-empty, and no further structure.
pub fn split(jwt: &[u8]) -> Result<Segments<'_>, OidcVerifyError> {
    let mut first: Option<usize> = None;
    let mut second: Option<usize> = None;
    for (i, &b) in jwt.iter().enumerate() {
        if b == b'.' {
            if first.is_none() {
                first = Some(i);
            } else if second.is_none() {
                second = Some(i);
            } else {
                return Err(OidcVerifyError::MalformedJwt); // a third dot
            }
        }
    }
    let (f, s) = match (first, second) {
        (Some(f), Some(s)) => (f, s),
        _ => return Err(OidcVerifyError::MalformedJwt),
    };
    // f < s is guaranteed by iteration order; require non-empty segments.
    if f == 0 || s == f + 1 || s + 1 >= jwt.len() {
        return Err(OidcVerifyError::MalformedJwt);
    }
    Ok(Segments {
        header_b64: &jwt[..f],
        payload_b64: &jwt[f + 1..s],
        sig_b64: &jwt[s + 1..],
        signing_input: &jwt[..s],
    })
}

/// base64url alphabet → 6-bit value; `0xFF` for anything outside it. Note: no
/// `+`, `/`, or `=` — those are rejected (`'+' == 0x2B`, `'/' == 0x2F`,
/// `'=' == 0x3D` all map to `0xFF`).
#[inline]
fn b64url_val(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => 0xFF,
    }
}

/// Strict base64url (no padding) decode of `src` into `out`. Returns the
/// decoded slice. Rejects: any non-alphabet byte; an input length `≡ 1 (mod 4)`
/// (impossible for base64); a decoded length larger than `out`; non-zero unused
/// bits in the final partial group (canonical-form enforcement).
pub fn b64url_decode_into<'o>(src: &[u8], out: &'o mut [u8]) -> Result<&'o [u8], OidcVerifyError> {
    let n = src.len();
    if n == 0 {
        return Err(OidcVerifyError::Base64Decode);
    }
    let rem = n % 4;
    if rem == 1 {
        return Err(OidcVerifyError::Base64Decode);
    }
    let full_groups = n / 4;
    let extra = rem; // 0, 2, or 3
    let decoded_len = full_groups * 3 + if extra == 0 { 0 } else { extra - 1 };
    if decoded_len > out.len() {
        return Err(OidcVerifyError::Base64Decode);
    }
    let mut oi = 0usize;
    let mut si = 0usize;
    // full 4-char groups → 3 bytes
    for _ in 0..full_groups {
        let a = b64url_val(src[si]);
        let b = b64url_val(src[si + 1]);
        let c = b64url_val(src[si + 2]);
        let d = b64url_val(src[si + 3]);
        if a | b | c | d == 0xFF || a == 0xFF || b == 0xFF || c == 0xFF || d == 0xFF {
            return Err(OidcVerifyError::Base64Decode);
        }
        let v = (a as u32) << 18 | (b as u32) << 12 | (c as u32) << 6 | (d as u32);
        out[oi] = (v >> 16) as u8;
        out[oi + 1] = (v >> 8) as u8;
        out[oi + 2] = v as u8;
        oi += 3;
        si += 4;
    }
    // trailing partial group
    if extra == 2 {
        // 2 chars → 1 byte; the low 4 bits of the 2nd char must be zero
        let a = b64url_val(src[si]);
        let b = b64url_val(src[si + 1]);
        if a == 0xFF || b == 0xFF {
            return Err(OidcVerifyError::Base64Decode);
        }
        if b & 0x0F != 0 {
            return Err(OidcVerifyError::Base64Decode);
        }
        out[oi] = (a << 2) | (b >> 4);
        oi += 1;
    } else if extra == 3 {
        // 3 chars → 2 bytes; the low 2 bits of the 3rd char must be zero
        let a = b64url_val(src[si]);
        let b = b64url_val(src[si + 1]);
        let c = b64url_val(src[si + 2]);
        if a == 0xFF || b == 0xFF || c == 0xFF {
            return Err(OidcVerifyError::Base64Decode);
        }
        if c & 0x03 != 0 {
            return Err(OidcVerifyError::Base64Decode);
        }
        out[oi] = (a << 2) | (b >> 4);
        out[oi + 1] = (b << 4) | (c >> 2);
        oi += 2;
    }
    debug_assert_eq!(oi, decoded_len);
    Ok(&out[..oi])
}

/// base64url-no-pad encoding of exactly 32 input bytes → 43 output bytes
/// (alphabet `A-Za-z0-9-_`). Mirrors `andromeda_auth`'s private encoder; used
/// to recompute the `oidc_nonce` claim value.
pub fn encode_base64url_nopad_32(input: &[u8; 32], out: &mut [u8; 43]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = 0usize;
    let mut i = 0usize;
    while i + 3 <= 30 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out[o] = ALPHABET[((n >> 18) & 0x3F) as usize];
        out[o + 1] = ALPHABET[((n >> 12) & 0x3F) as usize];
        out[o + 2] = ALPHABET[((n >> 6) & 0x3F) as usize];
        out[o + 3] = ALPHABET[(n & 0x3F) as usize];
        i += 3;
        o += 4;
    }
    // last 2 input bytes → 3 base64 chars (no pad)
    let n = ((input[30] as u32) << 8) | (input[31] as u32);
    out[o] = ALPHABET[((n >> 10) & 0x3F) as usize];
    out[o + 1] = ALPHABET[((n >> 4) & 0x3F) as usize];
    out[o + 2] = ALPHABET[((n << 2) & 0x3F) as usize];
}
