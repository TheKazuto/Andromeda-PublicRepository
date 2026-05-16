//! Strict JSON parsing of the JWT header and payload.
//!
//! This is the classic area for verifier bugs, so the parsing is deliberately
//! narrow (see `loginsocial.md` §6.7):
//!  * a proper object walk — values are *anchored* to their `"key":`, never
//!    found by scanning for a substring anywhere in the JSON;
//!  * duplicate top-level keys are rejected;
//!  * the header must declare `alg == "RS256"` and a `kid`, and must NOT carry
//!    `crit` / `jku` / `x5u` (or anything else that points at a remote key);
//!  * `aud` is accepted only as a string (an array `aud` is rejected — out of
//!    MVP scope);
//!  * the claims we compare (`iss`, `aud`, `sub`, `nonce`) must not contain a
//!    backslash escape (Google/Apple never escape these);
//!  * `iat` / `exp` / `nbf` must be plain non-negative decimal integers (no
//!    floats, no scientific notation, no leading zeros, bounded length).
//!
//! Nothing here makes an authentication decision — `verify()` only trusts these
//! values after the RSA signature check passes.

use crate::OidcVerifyError;

const E_HDR: OidcVerifyError = OidcVerifyError::MalformedHeader;
const E_CLAIMS: OidcVerifyError = OidcVerifyError::MalformedClaims;

// Reasonable bounds for the values we extract (well above what Google/Apple emit
// for an `openid`-scope id_token).
const MAX_KID_LEN: usize = 256;
const MAX_ISS_LEN: usize = 256;
const MAX_AUD_LEN: usize = 256;
const MAX_SUB_LEN: usize = 512;
const MAX_NONCE_LEN: usize = 64; // the canonical oidc_nonce is exactly 43 chars
const MAX_INT_DIGITS: usize = 11; // a Unix-seconds timestamp is 10 digits; 11 is slack
// M5 audit fix (2026-05-16): cap JSON nesting depth defensively. Real OIDC
// payloads are flat; 16 is far above plausible legit content and below the
// soft cap imposed by `MAX_PAYLOAD_DECODED = 1024`. Prevents pathological
// inputs from chewing CU budget walking deeply nested ignored fields.
const MAX_JSON_DEPTH: usize = 16;

#[derive(Debug)]
pub struct JwtHeader<'a> {
    pub kid: &'a [u8],
}

pub struct JwtClaims<'a> {
    pub iss: &'a [u8],
    pub aud: &'a [u8],
    pub sub: &'a [u8],
    pub nonce: &'a [u8],
    pub iat: i64,
    pub exp: i64,
    pub nbf: Option<i64>,
}

// ── tiny JSON scanner ──────────────────────────────────────────

struct Scanner<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Scanner<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, i: 0 }
    }
    fn peek(&self) -> Option<u8> {
        self.d.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let b = self.d.get(self.i).copied();
        if b.is_some() {
            self.i += 1;
        }
        b
    }
    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }
    fn at_end(&mut self) -> bool {
        self.skip_ws();
        self.i >= self.d.len()
    }

    /// Current byte must be `"`. Returns the raw bytes between the quotes (NOT
    /// unescaped) plus whether any backslash escape appeared. Handles `\"` and
    /// `\\` so the closing quote is found correctly; rejects an unterminated
    /// string and control bytes.
    fn parse_string_raw(&mut self, e: OidcVerifyError) -> Result<(&'a [u8], bool), OidcVerifyError> {
        if self.bump() != Some(b'"') {
            return Err(e);
        }
        let start = self.i;
        let mut has_backslash = false;
        loop {
            match self.bump() {
                None => return Err(e), // unterminated
                Some(b'"') => return Ok((&self.d[start..self.i - 1], has_backslash)),
                Some(b'\\') => {
                    has_backslash = true;
                    // M4 audit fix (2026-05-16): validate the escape byte
                    // against the JSON spec. Critical claims (iss/aud/sub/
                    // nonce/kid) are rejected when `has_backslash` is set,
                    // but enforcing strict JSON here closes the "junk passes
                    // through ignored fields" footgun for any future caller
                    // that consumes a non-critical claim from this scanner.
                    match self.bump() {
                        None => return Err(e),
                        Some(b'"') | Some(b'\\') | Some(b'/') | Some(b'b')
                        | Some(b'f') | Some(b'n') | Some(b'r') | Some(b't') => {}
                        Some(b'u') => {
                            // `\uXXXX` — require 4 hex digits.
                            for _ in 0..4 {
                                match self.bump() {
                                    Some(c) if c.is_ascii_hexdigit() => {}
                                    _ => return Err(e),
                                }
                            }
                        }
                        Some(_) => return Err(e),
                    }
                }
                Some(c) if c < 0x20 => return Err(e), // raw control byte — invalid JSON
                Some(_) => {}
            }
        }
    }

    /// Skip a JSON string value (current byte must be `"`).
    fn skip_string(&mut self, e: OidcVerifyError) -> Result<(), OidcVerifyError> {
        let _ = self.parse_string_raw(e)?;
        Ok(())
    }

    /// Skip a balanced `{...}` or `[...]` (current byte must be the opener),
    /// not counting brackets that appear inside strings.
    fn skip_balanced(&mut self, open: u8, close: u8, e: OidcVerifyError) -> Result<(), OidcVerifyError> {
        if self.bump() != Some(open) {
            return Err(e);
        }
        let mut depth = 1usize;
        loop {
            match self.peek() {
                None => return Err(e),
                Some(b'"') => self.skip_string(e)?,
                Some(b) if b == open => {
                    depth = depth.checked_add(1).ok_or(e)?;
                    if depth > MAX_JSON_DEPTH {
                        return Err(e);
                    }
                    self.i += 1;
                }
                Some(b) if b == close => {
                    depth -= 1;
                    self.i += 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Some(_) => self.i += 1,
            }
        }
    }

    /// Skip any JSON value: string / number / `true` / `false` / `null` /
    /// object / array.
    fn skip_value(&mut self, e: OidcVerifyError) -> Result<(), OidcVerifyError> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.skip_string(e),
            Some(b'{') => self.skip_balanced(b'{', b'}', e),
            Some(b'[') => self.skip_balanced(b'[', b']', e),
            Some(b't') => self.expect_literal(b"true", e),
            Some(b'f') => self.expect_literal(b"false", e),
            Some(b'n') => self.expect_literal(b"null", e),
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let _ = self.parse_number_raw(e)?;
                Ok(())
            }
            _ => Err(e),
        }
    }

    fn expect_literal(&mut self, lit: &[u8], e: OidcVerifyError) -> Result<(), OidcVerifyError> {
        if self.d.len() < self.i + lit.len() || &self.d[self.i..self.i + lit.len()] != lit {
            return Err(e);
        }
        self.i += lit.len();
        Ok(())
    }

    /// Parse a JSON number token, returning its raw bytes. Accepts the full JSON
    /// number grammar (so non-target numeric claims can be skipped); the strict
    /// integer check for `iat`/`exp`/`nbf` is done by [`parse_uint_seconds`].
    fn parse_number_raw(&mut self, e: OidcVerifyError) -> Result<&'a [u8], OidcVerifyError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut saw_digit = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => {
                    saw_digit = true;
                    self.i += 1;
                }
                b'.' | b'e' | b'E' | b'+' | b'-' => self.i += 1,
                _ => break,
            }
        }
        if !saw_digit {
            return Err(e);
        }
        Ok(&self.d[start..self.i])
    }
}

/// Strict non-negative decimal integer (seconds-since-epoch). Rejects: empty;
/// leading zero (except the single digit "0"); any non-digit; more than
/// `MAX_INT_DIGITS` digits. Returns the value as `i64`.
fn parse_uint_seconds(raw: &[u8], e: OidcVerifyError) -> Result<i64, OidcVerifyError> {
    if raw.is_empty() || raw.len() > MAX_INT_DIGITS {
        return Err(e);
    }
    if raw[0] == b'0' && raw.len() > 1 {
        return Err(e); // leading zero
    }
    let mut v: i64 = 0;
    for &c in raw {
        if !c.is_ascii_digit() {
            return Err(e);
        }
        v = v
            .checked_mul(10)
            .and_then(|x| x.checked_add((c - b'0') as i64))
            .ok_or(e)?;
    }
    Ok(v)
}

// ── object walk ────────────────────────────────────────────────

/// Walks a top-level JSON object, invoking `on_pair(key, key_has_backslash, scanner)`
/// for each `"key": value` pair. The callback MUST consume exactly the value
/// (parse it or `scanner.skip_value(...)`). Rejects structural errors and any
/// trailing bytes after the closing `}`.
fn walk_object<'a, F>(d: &'a [u8], e: OidcVerifyError, mut on_pair: F) -> Result<(), OidcVerifyError>
where
    F: FnMut(&'a [u8], bool, &mut Scanner<'a>) -> Result<(), OidcVerifyError>,
{
    let mut s = Scanner::new(d);
    s.skip_ws();
    if s.bump() != Some(b'{') {
        return Err(e);
    }
    s.skip_ws();
    if s.peek() == Some(b'}') {
        s.i += 1;
    } else {
        loop {
            s.skip_ws();
            if s.peek() != Some(b'"') {
                return Err(e);
            }
            let (key, key_bs) = s.parse_string_raw(e)?;
            s.skip_ws();
            if s.bump() != Some(b':') {
                return Err(e);
            }
            s.skip_ws();
            on_pair(key, key_bs, &mut s)?;
            s.skip_ws();
            match s.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(e),
            }
        }
    }
    if !s.at_end() {
        return Err(e); // trailing junk after the object
    }
    Ok(())
}

// ── helpers for "interesting key" handling ─────────────────────

/// Consume a string value, enforcing: no backslash escapes, length ≤ `max`,
/// and not-seen-before (`*seen` flag).
fn take_string<'a>(
    s: &mut Scanner<'a>,
    seen: &mut bool,
    max: usize,
    e: OidcVerifyError,
) -> Result<&'a [u8], OidcVerifyError> {
    if *seen {
        return Err(e); // duplicate key
    }
    if s.peek() != Some(b'"') {
        return Err(e);
    }
    let (val, has_bs) = s.parse_string_raw(e)?;
    if has_bs || val.len() > max {
        return Err(e);
    }
    *seen = true;
    Ok(val)
}

/// Consume an integer-seconds value, enforcing not-seen-before and the strict
/// integer grammar.
fn take_uint(s: &mut Scanner<'_>, seen: &mut bool, e: OidcVerifyError) -> Result<i64, OidcVerifyError> {
    if *seen {
        return Err(e);
    }
    let raw = s.parse_number_raw(e)?;
    let v = parse_uint_seconds(raw, e)?;
    *seen = true;
    Ok(v)
}

// ── public API ─────────────────────────────────────────────────

/// Parse the JWT JOSE header. Requires `alg == "RS256"` and a `kid`; rejects
/// `crit` / `jku` / `x5u`; rejects duplicate keys and bad escapes.
pub fn parse_header(header_json: &[u8]) -> Result<JwtHeader<'_>, OidcVerifyError> {
    let mut alg_seen = false;
    let mut kid: Option<&[u8]> = None;
    walk_object(header_json, E_HDR, |key, key_bs, s| {
        if key_bs {
            return Err(E_HDR); // a backslash in a header key is suspicious — reject outright
        }
        match key {
            b"crit" | b"jku" | b"x5u" => Err(E_HDR), // remote-key / extension headers not allowed
            b"alg" => {
                if alg_seen {
                    return Err(E_HDR);
                }
                if s.peek() != Some(b'"') {
                    return Err(E_HDR);
                }
                let (val, has_bs) = s.parse_string_raw(E_HDR)?;
                if has_bs {
                    return Err(E_HDR);
                }
                if val != b"RS256" {
                    return Err(OidcVerifyError::UnsupportedAlg);
                }
                alg_seen = true;
                Ok(())
            }
            b"kid" => {
                let mut seen = kid.is_some();
                let v = take_string(s, &mut seen, MAX_KID_LEN, E_HDR)?;
                kid = Some(v);
                Ok(())
            }
            _ => s.skip_value(E_HDR), // typ, cty, etc. — ignored
        }
    })?;
    if !alg_seen {
        return Err(E_HDR);
    }
    let kid = kid.ok_or(E_HDR)?;
    if kid.is_empty() {
        return Err(E_HDR);
    }
    Ok(JwtHeader { kid })
}

/// Parse the JWT payload claims. Requires `iss`, `aud`, `sub`, `nonce` (all
/// strings, `aud` not an array), `iat`, `exp` (integers); `nbf` is optional.
/// Rejects duplicate keys, bad escapes in the compared claims, malformed
/// numbers, and an array-valued `aud`.
pub fn parse_claims(payload_json: &[u8]) -> Result<JwtClaims<'_>, OidcVerifyError> {
    let mut iss: Option<&[u8]> = None;
    let mut aud: Option<&[u8]> = None;
    let mut sub: Option<&[u8]> = None;
    let mut nonce: Option<&[u8]> = None;
    let mut iat: Option<i64> = None;
    let mut exp: Option<i64> = None;
    let mut nbf: Option<i64> = None;

    walk_object(payload_json, E_CLAIMS, |key, key_bs, s| {
        match key {
            b"iss" => {
                if key_bs {
                    return Err(E_CLAIMS);
                }
                let mut seen = iss.is_some();
                iss = Some(take_string(s, &mut seen, MAX_ISS_LEN, E_CLAIMS)?);
                Ok(())
            }
            b"aud" => {
                if key_bs {
                    return Err(E_CLAIMS);
                }
                // MVP: only a string `aud`. An array (or object) `aud` is out of scope.
                if s.peek() == Some(b'[') {
                    return Err(E_CLAIMS);
                }
                let mut seen = aud.is_some();
                aud = Some(take_string(s, &mut seen, MAX_AUD_LEN, E_CLAIMS)?);
                Ok(())
            }
            b"sub" => {
                if key_bs {
                    return Err(E_CLAIMS);
                }
                let mut seen = sub.is_some();
                sub = Some(take_string(s, &mut seen, MAX_SUB_LEN, E_CLAIMS)?);
                Ok(())
            }
            b"nonce" => {
                if key_bs {
                    return Err(E_CLAIMS);
                }
                let mut seen = nonce.is_some();
                nonce = Some(take_string(s, &mut seen, MAX_NONCE_LEN, E_CLAIMS)?);
                Ok(())
            }
            b"iat" => {
                let mut seen = iat.is_some();
                iat = Some(take_uint(s, &mut seen, E_CLAIMS)?);
                Ok(())
            }
            b"exp" => {
                let mut seen = exp.is_some();
                exp = Some(take_uint(s, &mut seen, E_CLAIMS)?);
                Ok(())
            }
            b"nbf" => {
                let mut seen = nbf.is_some();
                nbf = Some(take_uint(s, &mut seen, E_CLAIMS)?);
                Ok(())
            }
            _ => s.skip_value(E_CLAIMS), // azp, at_hash, … — ignored
        }
    })?;

    let iss = iss.ok_or(E_CLAIMS)?;
    let aud = aud.ok_or(E_CLAIMS)?;
    let sub = sub.ok_or(E_CLAIMS)?;
    let nonce = nonce.ok_or(E_CLAIMS)?;
    let iat = iat.ok_or(E_CLAIMS)?;
    let exp = exp.ok_or(E_CLAIMS)?;
    if iss.is_empty() || aud.is_empty() || sub.is_empty() || nonce.is_empty() {
        return Err(E_CLAIMS);
    }
    Ok(JwtClaims { iss, aud, sub, nonce, iat, exp, nbf })
}
