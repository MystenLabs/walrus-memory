use aes_gcm::{aead::Payload, AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{fmt, time::Duration};
use zeroize::Zeroizing;

use super::email::EmailAddress;

#[derive(Clone)]
pub(super) struct SecretKey32(Zeroizing<[u8; 32]>);

impl fmt::Debug for SecretKey32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl SecretKey32 {
    fn parse(raw: &str) -> Option<Self> {
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(raw.trim()).ok()?);
        let bytes = <&[u8; 32]>::try_from(decoded.as_slice()).ok()?;
        Some(Self(Zeroizing::new(*bytes)))
    }

    fn load(name: &str) -> Self {
        let raw = Zeroizing::new(std::env::var(name).unwrap_or_default());
        Self::parse(&raw)
            .unwrap_or_else(|| panic!("{name} must be a base64url-encoded 32-byte key"))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MarketingConsentConfig {
    pub(super) encryption_key: SecretKey32,
    pub(super) hash_key: SecretKey32,
    pub(super) erasure_interval: Duration,
}

impl MarketingConsentConfig {
    pub(super) fn hash_key_bytes(&self) -> &[u8] {
        self.hash_key.0.as_ref()
    }
    pub(crate) fn from_env(enabled: bool) -> Option<Self> {
        enabled.then(|| {
            let encryption_key = SecretKey32::load("MARKETING_CONSENT_ENCRYPTION_KEY");
            let hash_key = SecretKey32::load("MARKETING_CONSENT_HASH_KEY");
            assert!(
                !crate::oauth::constant_time_eq(encryption_key.0.as_ref(), hash_key.0.as_ref()),
                "Marketing consent requires separate encryption and hash keys"
            );
            let erasure_secs = std::env::var("MARKETING_CONSENT_ERASURE_INTERVAL_SECS")
                .map(|value| {
                    value.parse::<u32>().ok().filter(|secs| *secs > 0).expect(
                        "MARKETING_CONSENT_ERASURE_INTERVAL_SECS must be a positive integer",
                    )
                })
                .unwrap_or(3600);
            Self {
                encryption_key,
                hash_key,
                erasure_interval: Duration::from_secs(erasure_secs.into()),
            }
        })
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self {
            encryption_key: SecretKey32(Zeroizing::new([1; 32])),
            hash_key: SecretKey32(Zeroizing::new([2; 32])),
            erasure_interval: Duration::from_secs(3600),
        }
    }
}

const AAD_PREFIX: &str = "memwal/marketing_consent/v1/";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct CryptoError;

pub(super) fn encrypt(
    key: &SecretKey32,
    owner: &str,
    email: &EmailAddress,
) -> Result<String, CryptoError> {
    use aes_gcm::aead::Aead;
    let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| CryptoError)?;
    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| CryptoError)?;
    let aad = format!("{AAD_PREFIX}{owner}");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: email.expose().as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError)?;
    Ok(format!(
        "v1.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

pub(super) fn decrypt(
    key: &SecretKey32,
    owner: &str,
    envelope: &str,
) -> Result<EmailAddress, CryptoError> {
    let mut parts = envelope.splitn(3, '.');
    if parts.next() != Some("v1") {
        return Err(CryptoError);
    }
    let nonce: [u8; 12] = URL_SAFE_NO_PAD
        .decode(parts.next().ok_or(CryptoError)?)
        .map_err(|_| CryptoError)?
        .try_into()
        .map_err(|_| CryptoError)?;
    let mut plaintext = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(parts.next().ok_or(CryptoError)?)
            .map_err(|_| CryptoError)?,
    );
    let aad = format!("{AAD_PREFIX}{owner}");
    let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| CryptoError)?;
    cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), aad.as_bytes(), &mut *plaintext)
        .map_err(|_| CryptoError)?;
    EmailAddress::parse(std::str::from_utf8(&plaintext).map_err(|_| CryptoError)?)
        .ok_or(CryptoError)
}

pub(super) fn address_hash(key: &SecretKey32, email: &EmailAddress) -> String {
    keyed_hash(
        key,
        b"memwal/marketing_consent/address/v1:",
        &[email.expose().as_bytes()],
    )
}

pub(super) fn keyed_hash(key: &SecretKey32, domain: &[u8], parts: &[&[u8]]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.0.as_ref()).expect("valid HMAC key");
    mac.update(domain);
    for part in parts {
        mac.update(part);
    }
    hex::encode(mac.finalize().into_bytes())
}
