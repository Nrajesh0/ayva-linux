/*
 * Ayva for Fedora GNOME 44+
 * XChaCha20-Poly1305 Per-Note Envelope Encryption (RFC 8439 / libsodium extension)
 *
 * Implements authenticated envelope encryption with:
 * - 256-bit symmetric keys derived from HKDF "ayva_vault_v1"
 * - 192-bit (24-byte) random nonces (eliminating collision probability)
 * - 128-bit Poly1305 authentication tags (guaranteeing integrity and authenticity)
 * - Typed `DecryptionResult` handling corruption, wrong key, and vault-locked states
 */

use crate::crypto::memlock::KeyBuffer32;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub const ENVELOPE_PREFIX_V2: &str = "ENC_VAULT_V2";
pub const CURRENT_KEY_VERSION: u32 = 1;
pub const XCHACHA20_NONCE_SIZE: usize = 24;

#[derive(Debug)]
pub enum EnvelopeError {
    EncryptionFailed(String),
    ParseError(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed(s) => write!(f, "Envelope encryption failed: {}", s),
            Self::ParseError(s) => write!(f, "Envelope parse error: {}", s),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Typed result of an envelope decryption operation
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptionResult {
    /// Note successfully decrypted
    Success(Vec<u8>),
    /// AEAD tag validation failed (either incorrect key or corrupted payload)
    AuthFailed,
    /// Envelope format is malformed or invalid
    Malformed(String),
}

/// Structured per-note cryptographic envelope
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultEnvelope {
    pub version: u32,
    pub nonce: [u8; XCHACHA20_NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

impl VaultEnvelope {
    /// Encrypts `plaintext` with `key` using XChaCha20-Poly1305 and a fresh 192-bit OS random nonce.
    pub fn encrypt(plaintext: &[u8], key: &KeyBuffer32, version: u32) -> Result<Self, EnvelopeError> {
        let mut nonce_bytes = [0u8; XCHACHA20_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|e| EnvelopeError::EncryptionFailed(e.to_string()))?;

        let xnonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(xnonce, plaintext)
            .map_err(|e| EnvelopeError::EncryptionFailed(e.to_string()))?;

        Ok(Self {
            version,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypts this envelope using `key`. Returns a typed DecryptionResult.
    pub fn decrypt(&self, key: &KeyBuffer32) -> DecryptionResult {
        let cipher = match XChaCha20Poly1305::new_from_slice(key.as_slice()) {
            Ok(c) => c,
            Err(_) => return DecryptionResult::AuthFailed,
        };

        let xnonce = XNonce::from_slice(&self.nonce);
        match cipher.decrypt(xnonce, self.ciphertext.as_ref()) {
            Ok(plaintext) => DecryptionResult::Success(plaintext),
            Err(_) => DecryptionResult::AuthFailed,
        }
    }

    /// Serializes envelope to standard text format:
    /// `ENC_VAULT_V2:kv=<version>:<nonce_hex>:<ciphertext_hex>`
    pub fn serialize(&self) -> String {
        format!(
            "{}:kv={}:{}:{}",
            ENVELOPE_PREFIX_V2,
            self.version,
            to_hex(&self.nonce),
            to_hex(&self.ciphertext)
        )
    }

    /// Parses a serialized envelope string
    pub fn parse(serialized: &str) -> Result<Self, EnvelopeError> {
        let parts: Vec<&str> = serialized.split(':').collect();
        if parts.len() != 4 {
            return Err(EnvelopeError::ParseError(
                "Invalid envelope field count; expected 4 parts separated by ':'".to_string(),
            ));
        }

        if parts[0] != ENVELOPE_PREFIX_V2 {
            return Err(EnvelopeError::ParseError(format!(
                "Unsupported envelope prefix '{}'; expected '{}'",
                parts[0], ENVELOPE_PREFIX_V2
            )));
        }

        if !parts[1].starts_with("kv=") {
            return Err(EnvelopeError::ParseError(
                "Missing 'kv=' key version field in envelope header".to_string(),
            ));
        }

        let version = parts[1][3..]
            .parse::<u32>()
            .map_err(|e| EnvelopeError::ParseError(format!("Invalid key version number: {}", e)))?;

        let nonce_vec = from_hex(parts[2])
            .map_err(|e| EnvelopeError::ParseError(format!("Invalid nonce hex: {}", e)))?;

        if nonce_vec.len() != XCHACHA20_NONCE_SIZE {
            return Err(EnvelopeError::ParseError(format!(
                "Invalid nonce length: expected {} bytes, got {}",
                XCHACHA20_NONCE_SIZE,
                nonce_vec.len()
            )));
        }

        let mut nonce = [0u8; XCHACHA20_NONCE_SIZE];
        nonce.copy_from_slice(&nonce_vec);

        let ciphertext = from_hex(parts[3])
            .map_err(|e| EnvelopeError::ParseError(format!("Invalid ciphertext hex: {}", e)))?;

        Ok(Self {
            version,
            nonce,
            ciphertext,
        })
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex digit at index {}: {}", i, e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip_encryption_decryption() {
        let key = KeyBuffer32::new([0x42; 32]);
        let secret_payload = b"Ayva top-secret rich note block contents";

        let envelope = VaultEnvelope::encrypt(secret_payload, &key, CURRENT_KEY_VERSION)
            .expect("encryption failed");

        assert_eq!(envelope.version, CURRENT_KEY_VERSION);
        assert_ne!(envelope.ciphertext, secret_payload);

        let decrypted = envelope.decrypt(&key);
        match decrypted {
            DecryptionResult::Success(data) => assert_eq!(data, secret_payload),
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_envelope_wrong_key_fails_authentication() {
        let key1 = KeyBuffer32::new([0x01; 32]);
        let key2 = KeyBuffer32::new([0x02; 32]);
        let secret = b"Sensitive note data";

        let envelope = VaultEnvelope::encrypt(secret, &key1, 1).unwrap();
        let result = envelope.decrypt(&key2);

        assert_eq!(result, DecryptionResult::AuthFailed);
    }

    #[test]
    fn test_envelope_tamper_detection_bitflip() {
        let key = KeyBuffer32::new([0x55; 32]);
        let secret = b"Critical financial note";

        let mut envelope = VaultEnvelope::encrypt(secret, &key, 1).unwrap();

        // Flip a bit in the ciphertext / Poly1305 tag
        if let Some(byte) = envelope.ciphertext.last_mut() {
            *byte ^= 0x01;
        }

        let result = envelope.decrypt(&key);
        assert_eq!(result, DecryptionResult::AuthFailed, "Bit flip must fail Poly1305 auth tag");
    }

    #[test]
    fn test_envelope_serialization_and_parsing_roundtrip() {
        let key = KeyBuffer32::new([0x88; 32]);
        let plaintext = b"Block model test json";

        let envelope = VaultEnvelope::encrypt(plaintext, &key, 1).unwrap();
        let serialized = envelope.serialize();

        assert!(serialized.starts_with("ENC_VAULT_V2:kv=1:"));

        let parsed = VaultEnvelope::parse(&serialized).expect("parse failed");
        assert_eq!(parsed, envelope);

        let decrypted = parsed.decrypt(&key);
        assert_eq!(decrypted, DecryptionResult::Success(plaintext.to_vec()));
    }
}
