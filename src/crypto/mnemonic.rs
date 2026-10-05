/*
 * Ayva for Fedora GNOME 44+
 * BIP-39 12-Word Emergency Recovery Engine
 *
 * Implements deterministic mnemonic phrase generation and master key
 * recovery envelopes, allowing users to restore their encrypted notes
 * if they forget their 6-digit PIN.
 */

use crate::crypto::envelope::{DecryptionResult, VaultEnvelope, CURRENT_KEY_VERSION};
use crate::crypto::memlock::KeyBuffer32;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroize;

pub const DOMAIN_RECOVERY: &[u8] = b"ayva_recovery_v1";

#[derive(Debug)]
pub enum MnemonicError {
    GenerationFailed(String),
    InvalidPhrase(String),
    DerivationFailed(String),
    RecoveryFailed(String),
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenerationFailed(s) => write!(f, "Mnemonic generation error: {}", s),
            Self::InvalidPhrase(s) => write!(f, "Invalid BIP-39 mnemonic phrase: {}", s),
            Self::DerivationFailed(s) => write!(f, "Recovery key derivation failed: {}", s),
            Self::RecoveryFailed(s) => write!(f, "Vault recovery failed: {}", s),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// Generates a fresh 12-word BIP-39 English mnemonic phrase using 128-bit OS entropy
pub fn generate_mnemonic_phrase() -> Result<String, MnemonicError> {
    let mut rng = OsRng;
    let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 12)
        .map_err(|e| MnemonicError::GenerationFailed(e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Derives a 256-bit recovery key from a 12-word mnemonic phrase using BIP-39 seed + HKDF
pub fn derive_recovery_key(phrase: &str) -> Result<KeyBuffer32, MnemonicError> {
    let normalized = phrase.trim();
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, normalized)
        .map_err(|e| MnemonicError::InvalidPhrase(e.to_string()))?;

    // BIP-39 PBKDF2-HMAC-SHA512 seed generation (64 bytes = 512 bits)
    let mut seed = mnemonic.to_seed("");

    // Expand into 256-bit recovery key via HKDF domain separation
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut okm = [0u8; 32];
    hk.expand(DOMAIN_RECOVERY, &mut okm)
        .map_err(|e| MnemonicError::DerivationFailed(e.to_string()))?;

    let recovery_key = KeyBuffer32::new(okm);

    // Zeroize sensitive temporary buffers
    seed.zeroize();
    okm.zeroize();

    Ok(recovery_key)
}

/// Encrypts the Master Vault Key into a recovery envelope using the recovery key
pub fn create_recovery_envelope(
    master_key: &KeyBuffer32,
    recovery_key: &KeyBuffer32,
) -> Result<VaultEnvelope, MnemonicError> {
    VaultEnvelope::encrypt(master_key.as_slice(), recovery_key, CURRENT_KEY_VERSION)
        .map_err(|e| MnemonicError::RecoveryFailed(e.to_string()))
}

/// Restores the Master Vault Key from a recovery envelope using the recovery key
pub fn restore_master_key_from_envelope(
    recovery_envelope: &VaultEnvelope,
    recovery_key: &KeyBuffer32,
) -> Result<KeyBuffer32, MnemonicError> {
    match recovery_envelope.decrypt(recovery_key) {
        DecryptionResult::Success(raw_bytes) => {
            if raw_bytes.len() != 32 {
                return Err(MnemonicError::RecoveryFailed(format!(
                    "Decrypted master key has invalid length: expected 32, got {}",
                    raw_bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw_bytes);
            let restored = KeyBuffer32::new(arr);
            arr.zeroize();
            Ok(restored)
        }
        DecryptionResult::AuthFailed => Err(MnemonicError::RecoveryFailed(
            "Authentication failed: recovery phrase is incorrect or envelope is corrupted".to_string(),
        )),
        DecryptionResult::Malformed(msg) => Err(MnemonicError::RecoveryFailed(msg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_generate_and_parse_valid_mnemonic() {
        let phrase = generate_mnemonic_phrase().expect("failed to generate mnemonic");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12, "Must generate exactly 12 words");

        // Verify recovery key derivation succeeds
        let key = derive_recovery_key(&phrase);
        assert!(key.is_ok());
    }

    #[test]
    fn test_mnemonic_recovery_envelope_roundtrip() {
        let master_key = KeyBuffer32::new([0x99; 32]);

        // User sets up vault and gets 12-word mnemonic
        let phrase = generate_mnemonic_phrase().unwrap();
        let recovery_key = derive_recovery_key(&phrase).unwrap();

        // System creates recovery envelope and saves it in database
        let envelope = create_recovery_envelope(&master_key, &recovery_key).unwrap();

        // User forgets PIN and inputs the 12 words
        let entered_recovery_key = derive_recovery_key(&phrase).unwrap();
        let restored_master_key =
            restore_master_key_from_envelope(&envelope, &entered_recovery_key).unwrap();

        assert!(
            bool::from(master_key.ct_eq(&restored_master_key)),
            "Restored master key must match original"
        );
    }

    #[test]
    fn test_wrong_mnemonic_fails_restore() {
        let master_key = KeyBuffer32::new([0x3a; 32]);

        let phrase1 = generate_mnemonic_phrase().unwrap();
        let phrase2 = generate_mnemonic_phrase().unwrap();

        let recovery_key1 = derive_recovery_key(&phrase1).unwrap();
        let recovery_key2 = derive_recovery_key(&phrase2).unwrap();

        let envelope = create_recovery_envelope(&master_key, &recovery_key1).unwrap();

        let result = restore_master_key_from_envelope(&envelope, &recovery_key2);
        assert!(result.is_err(), "Wrong mnemonic phrase must fail to decrypt envelope");
    }

    #[test]
    fn test_invalid_mnemonic_phrase_format() {
        let invalid_phrase = "apple banana orange not enough words";
        let result = derive_recovery_key(invalid_phrase);
        assert!(result.is_err());
    }
}
