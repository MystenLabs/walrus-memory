//! Ed25519 request signing, Sui address derivation, Bech32 `suiprivkey` encoding,
//! SEAL session personal message signing, and deterministic idempotency keys.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use chrono::{TimeZone as _, Utc};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type Blake2b256 = Blake2b<U32>;

/// Sui Ed25519 signature scheme flag byte (`0x00`).
const SUI_ED25519_FLAG: u8 = 0x00;

/// Sui Bech32 private key human-readable part.
const SUI_PRIVKEY_HRP: &str = "suiprivkey";

/// Standard Bech32 alphabet (`BIP-0173`).
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// 30-minute window in milliseconds used for automatic retry idempotency keys.
pub(crate) const IDEMPOTENCY_BUCKET_MS: u128 = 30 * 60 * 1_000;

/// Zeroize-on-drop Ed25519 delegate key signer.
///
/// [`Debug`] formatting redacts the secret key while preserving the public key
/// hex for diagnostics.
pub(crate) struct Signer {
    signing_key: SigningKey,
    public_key_hex: String,
    sui_address: String,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("public_key", &self.public_key_hex)
            .field("sui_address", &self.sui_address)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl Signer {
    /// Parses a delegate private key from 64-character hex, `0x`-prefixed hex,
    /// or a Sui `suiprivkey1...` Bech32 Ed25519 key string.
    pub(crate) fn from_key_str(raw: &str) -> Result<Self> {
        let seed = normalize_private_key_bytes(raw)?;
        Ok(Self::from_seed_array(&seed))
    }

    /// Builds a signer by copying a 32-byte Ed25519 secret seed into a
    /// zeroizing internal buffer without mutating the caller slice.
    pub(crate) fn from_seed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidKey(format!(
                "expected 32-byte Ed25519 seed, got {} bytes",
                bytes.len()
            )));
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(bytes);
        Ok(Self::from_seed_array(&seed))
    }

    fn from_seed_array(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        let sui_address = sui_address_from_verifying_key(&verifying_key);
        Self {
            signing_key,
            public_key_hex,
            sui_address,
        }
    }

    pub(crate) fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    pub(crate) fn sui_address(&self) -> &str {
        &self.sui_address
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs raw message bytes with Ed25519 and returns lowercase hex (`128` chars).
    pub(crate) fn sign_hex(&self, message: &[u8]) -> String {
        let sig = self.signing_key.sign(message);
        hex::encode(sig.to_bytes())
    }

    pub(crate) fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Parses a hex (`64` chars, optional `0x`/`0X` prefix) or `suiprivkey1...`
/// string into a zeroizing 32-byte Ed25519 seed.
pub(crate) fn normalize_private_key_bytes(raw: &str) -> Result<Zeroizing<[u8; 32]>> {
    if raw.is_empty() {
        return Err(Error::InvalidKey("private key cannot be empty".to_owned()));
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(Error::InvalidKey(
            "private key must not contain whitespace".to_owned(),
        ));
    }

    if raw
        .get(..SUI_PRIVKEY_HRP.len() + 1)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("suiprivkey1"))
    {
        return decode_sui_private_key(raw);
    }

    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);

    if stripped.len() != 64 {
        return Err(Error::InvalidKey(format!(
            "expected 64 hex characters (32 bytes), got {} characters",
            stripped.len()
        )));
    }

    let mut seed = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(stripped, &mut *seed)
        .map_err(|err| Error::InvalidKey(format!("invalid hex character in key: {err}")))?;
    Ok(seed)
}

/// Derives the 64-character lowercase hex Ed25519 public key from a delegate key.
///
/// Accepts 64-character hex, `0x`-prefixed hex, or `suiprivkey1...` Bech32 strings.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `private_key` is empty, malformed, or uses a
/// non-Ed25519 Sui key scheme.
///
/// # Examples
///
/// ```
/// let key = "1111111111111111111111111111111111111111111111111111111111111111";
/// let pubkey = memwal::delegate_key_to_public_key_hex(key)?;
/// assert_eq!(pubkey.len(), 64);
/// # Ok::<(), memwal::Error>(())
/// ```
pub fn delegate_key_to_public_key_hex(private_key: &str) -> Result<String> {
    let signer = Signer::from_key_str(private_key)?;
    Ok(signer.public_key_hex().to_owned())
}

/// Derives the `0x`-prefixed Sui address (`blake2b256(0x00 || pubkey)`) for an
/// Ed25519 delegate private key.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `private_key` cannot be parsed as a valid
/// Ed25519 private key.
///
/// # Examples
///
/// ```
/// let key = "1111111111111111111111111111111111111111111111111111111111111111";
/// let address = memwal::delegate_key_to_sui_address(key)?;
/// assert!(address.starts_with("0x"));
/// assert_eq!(address.len(), 66);
/// # Ok::<(), memwal::Error>(())
/// ```
pub fn delegate_key_to_sui_address(private_key: &str) -> Result<String> {
    let signer = Signer::from_key_str(private_key)?;
    Ok(signer.sui_address().to_owned())
}

/// Computes the lowercase hex SHA-256 digest of `data`.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     memwal::sha256_hex(b""),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// ```
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Builds the canonical Walrus Memory Ed25519 signing payload:
/// `{timestamp}.{method}.{path_and_query}.{sha256(body)}.{nonce}.{account_id}`.
#[must_use]
pub fn canonical_message(
    timestamp: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    nonce: &str,
    account_id: &str,
) -> String {
    let body_hash = sha256_hex(body);
    format!("{timestamp}.{method}.{path_and_query}.{body_hash}.{nonce}.{account_id}")
}

/// Computes `0x` + `blake2b256(0x00 || verifying_key)`.
pub(crate) fn sui_address_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    let mut payload = [0_u8; 33];
    payload[0] = SUI_ED25519_FLAG;
    payload[1..].copy_from_slice(verifying_key.as_bytes());
    let digest = blake2b_256(&payload);
    format!("0x{}", hex::encode(digest))
}

pub(crate) fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Encodes an unsigned integer using BCS ULEB128 variable-length encoding.
pub(crate) fn encode_uleb128(mut value: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Builds the SEAL `SessionKey` personal message expected by Mysten SEAL key servers:
/// `Accessing keys of package {package_id} for {ttl_min} mins from {YYYY-MM-DD HH:MM:SS UTC}, session key {session_pubkey_b64}`.
pub(crate) fn build_seal_session_personal_message(
    package_id: &str,
    ttl_min: u64,
    creation_time_ms: u64,
    session_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let millis = i64::try_from(creation_time_ms)
        .map_err(|_| Error::SealSession("session creation timestamp overflowed i64".to_owned()))?;
    let dt = Utc
        .timestamp_millis_opt(millis)
        .single()
        .ok_or_else(|| Error::SealSession("invalid session creation timestamp".to_owned()))?;
    let formatted_utc = dt.format("%Y-%m-%d %H:%M:%S UTC");
    let pubkey_b64 = BASE64_STANDARD.encode(session_public_key);
    let msg = format!(
        "Accessing keys of package {package_id} for {ttl_min} mins from {formatted_utc}, session key {pubkey_b64}"
    );
    Ok(msg.into_bytes())
}

/// Signs a Sui `PersonalMessage` (`intent = [3, 0, 0] || bcs_bytes(message)`)
/// and returns the 97-byte serialized Sui signature (`0x00 || sig64 || pubkey32`)
/// encoded as standard Base64.
pub(crate) fn sign_sui_personal_message(message: &[u8], signer: &Signer) -> String {
    let uleb_len = encode_uleb128(message.len());
    let mut intent_msg = Vec::with_capacity(3 + uleb_len.len() + message.len());
    intent_msg.extend_from_slice(&[0x03, 0x00, 0x00]);
    intent_msg.extend_from_slice(&uleb_len);
    intent_msg.extend_from_slice(message);

    let digest = blake2b_256(&intent_msg);
    let sig_bytes = signer.sign_raw(&digest);
    let pub_bytes = signer.verifying_key().to_bytes();

    let mut serialized = [0_u8; 97];
    serialized[0] = SUI_ED25519_FLAG;
    serialized[1..65].copy_from_slice(&sig_bytes);
    serialized[65..97].copy_from_slice(&pub_bytes);

    BASE64_STANDARD.encode(serialized)
}

/// Encodes a 32-byte Ed25519 secret seed as a Sui `suiprivkey1...` Bech32 string.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if Bech32 bit conversion fails.
pub fn encode_sui_private_key(seed: &[u8; 32]) -> Result<String> {
    let mut raw = Zeroizing::new([0_u8; 33]);
    raw[0] = SUI_ED25519_FLAG;
    raw[1..].copy_from_slice(seed);
    let words = convert_bits(&raw[..], 8, 5, BitPadding::Pad)?;
    Ok(bech32_encode(SUI_PRIVKEY_HRP, &words))
}

/// Decodes a Sui `suiprivkey1...` Bech32 string into a zeroizing 32-byte Ed25519 seed.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if the HRP, checksum, key length, or scheme flag
/// is invalid (non-Ed25519 keys are rejected).
pub fn decode_sui_private_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let (hrp, data) = bech32_decode(encoded)?;
    if hrp != SUI_PRIVKEY_HRP {
        return Err(Error::InvalidKey(format!(
            "unexpected Bech32 prefix {hrp:?}; expected {SUI_PRIVKEY_HRP:?}"
        )));
    }
    let decoded = Zeroizing::new(convert_bits(&data, 5, 8, BitPadding::NoPad)?);
    if decoded.len() != 33 {
        return Err(Error::InvalidKey(format!(
            "invalid suiprivkey payload length: expected 33 bytes, got {}",
            decoded.len()
        )));
    }
    let scheme = decoded[0];
    if scheme != SUI_ED25519_FLAG {
        return Err(Error::InvalidKey(format!(
            "unsupported Sui key scheme flag 0x{scheme:02x}; MemWal requires Ed25519 (0x00)"
        )));
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&decoded[1..33]);
    Ok(seed)
}

pub(crate) fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

pub(crate) fn derived_idempotency_key(request_identity: &str) -> String {
    let bucket = now_epoch_ms() / IDEMPOTENCY_BUCKET_MS;
    let material = format!("{bucket}\0{request_identity}");
    format!("r1-{}", sha256_hex(material.as_bytes()))
}

pub(crate) fn derived_content_dedupe_key(request_identity: &str) -> String {
    format!("dedupe:{}", sha256_hex(request_identity.as_bytes()))
}

pub(crate) fn derived_bulk_idempotency_key(request_identity: &str) -> String {
    let bucket = now_epoch_ms() / IDEMPOTENCY_BUCKET_MS;
    let material = format!("{bucket}\0{request_identity}");
    format!("b1-{}", sha256_hex(material.as_bytes()))
}

// ============================================================
// Pure-Rust BIP-0173 Bech32 codec (zero unwrap)
// ============================================================

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 0x1f);
    }
    out
}

fn bech32_create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0_u8; 6]);
    let polymod = bech32_polymod(&values) ^ 1;
    let mut checksum = [0_u8; 6];
    for (i, slot) in checksum.iter_mut().enumerate() {
        *slot = u8::try_from((polymod >> (5 * (5 - i))) & 0x1f).unwrap_or(0);
    }
    checksum
}

fn bech32_verify_checksum(hrp: &str, data_with_checksum: &[u8]) -> bool {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data_with_checksum);
    bech32_polymod(&values) == 1
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let checksum = bech32_create_checksum(hrp, data);
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + checksum.len());
    out.push_str(hrp);
    out.push('1');
    for &word in data.iter().chain(checksum.iter()) {
        let idx = usize::from(word & 0x1f);
        out.push(char::from(BECH32_CHARSET[idx]));
    }
    out
}

fn bech32_decode(encoded: &str) -> Result<(String, Vec<u8>)> {
    if encoded.len() < 8 || encoded.len() > 90 {
        return Err(Error::InvalidKey("invalid Bech32 key length".to_owned()));
    }
    let mut has_lower = false;
    let mut has_upper = false;
    for b in encoded.bytes() {
        if !(33..=126).contains(&b) {
            return Err(Error::InvalidKey(
                "invalid ASCII character in Bech32 key".to_owned(),
            ));
        }
        if b.is_ascii_lowercase() {
            has_lower = true;
        }
        if b.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    if has_lower && has_upper {
        return Err(Error::InvalidKey(
            "mixed-case Bech32 key is not allowed".to_owned(),
        ));
    }

    let lower = encoded.to_ascii_lowercase();
    let sep_pos = lower
        .rfind('1')
        .ok_or_else(|| Error::InvalidKey("Bech32 separator '1' missing".to_owned()))?;
    if sep_pos == 0 || sep_pos + 7 > lower.len() {
        return Err(Error::InvalidKey(
            "invalid Bech32 separator position or checksum length".to_owned(),
        ));
    }

    let hrp = lower[..sep_pos].to_owned();
    let data_part = &lower[sep_pos + 1..];
    let mut words = Vec::with_capacity(data_part.len());
    for ch in data_part.bytes() {
        let pos = BECH32_CHARSET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| {
                Error::InvalidKey(format!("invalid Bech32 character '{}'", char::from(ch)))
            })?;
        words.push(u8::try_from(pos).unwrap_or(0));
    }

    if !bech32_verify_checksum(&hrp, &words) {
        return Err(Error::InvalidKey(
            "Bech32 checksum verification failed".to_owned(),
        ));
    }

    words.truncate(words.len() - 6);
    Ok((hrp, words))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BitPadding {
    Pad,
    NoPad,
}

fn convert_bits(data: &[u8], from_bits: u8, to_bits: u8, padding: BitPadding) -> Result<Vec<u8>> {
    let from = u32::from(from_bits);
    let to = u32::from(to_bits);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    let mut out =
        Vec::with_capacity((data.len() * usize::from(from_bits)).div_ceil(usize::from(to_bits)));

    for &value in data {
        let v = u32::from(value);
        if (v >> from) != 0 {
            return Err(Error::InvalidKey("Bech32 word out of range".to_owned()));
        }
        acc = ((acc << from) | v) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(u8::try_from((acc >> bits) & maxv).unwrap_or(0));
        }
    }

    if padding == BitPadding::Pad {
        if bits > 0 {
            out.push(u8::try_from((acc << (to - bits)) & maxv).unwrap_or(0));
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::InvalidKey(
            "non-zero padding bits in Bech32 payload".to_owned(),
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suiprivkey_round_trip_and_redacted_debug() {
        let seed = [0x42_u8; 32];
        let encoded = encode_sui_private_key(&seed).expect("encode suiprivkey");
        assert!(encoded.starts_with("suiprivkey1"));

        let decoded = decode_sui_private_key(&encoded).expect("decode suiprivkey");
        assert_eq!(&*decoded, &seed);

        let signer_from_bech32 = Signer::from_key_str(&encoded).expect("parse bech32");
        let hex_key = hex::encode(seed);
        let signer_from_hex = Signer::from_key_str(&hex_key).expect("parse hex");
        assert_eq!(
            signer_from_bech32.public_key_hex(),
            signer_from_hex.public_key_hex()
        );
        assert_eq!(
            signer_from_bech32.sui_address(),
            signer_from_hex.sui_address()
        );

        let dbg = format!("{signer_from_hex:?}");
        assert!(!dbg.contains(&hex_key));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn non_ed25519_suiprivkey_is_rejected() {
        let mut secp_payload = [0_u8; 33];
        secp_payload[0] = 0x01; // Secp256k1 scheme flag
        secp_payload[1..].copy_from_slice(&[0x11_u8; 32]);
        let words = convert_bits(&secp_payload, 8, 5, BitPadding::Pad).expect("convert bits");
        let encoded = bech32_encode(SUI_PRIVKEY_HRP, &words);

        let err = decode_sui_private_key(&encoded).expect_err("secp256k1 flag must fail");
        assert!(matches!(err, Error::InvalidKey(_)));
        assert!(err.to_string().contains("0x01"));
    }

    #[test]
    fn seed_bytes_are_copied_without_mutating_caller() {
        let caller = [0x7a_u8; 32];
        let signer = Signer::from_seed_bytes(&caller).expect("from seed bytes");
        assert_eq!(caller, [0x7a_u8; 32]);
        assert_eq!(signer.public_key_hex().len(), 64);
    }

    #[test]
    fn canonical_message_matches_relayer_auth_wire_format() {
        let msg = canonical_message(
            "1700000000",
            "GET",
            "/api/whoami",
            b"",
            "550e8400-e29b-41d4-a716-446655440000",
            "0xabc123",
        );
        assert_eq!(
            msg,
            "1700000000.GET./api/whoami.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.550e8400-e29b-41d4-a716-446655440000.0xabc123"
        );
    }
}
