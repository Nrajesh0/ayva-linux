/*
 * Ayva for Fedora GNOME 44+
 * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 *
 * Enforces cryptographic domain separation from the Master Vault Key:
 * - "ayva_db_v1"    -> Database page encryption key for SQLCipher
 * - "ayva_vault_v1" -> Per-note envelope cipher key (XChaCha20-Poly1305)
 * - "ayva_hmac_v1"  -> Integrity and tamper-detection signing key
 */

use crate::crypto::memlock::KeyBuffer32;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

pub const DOMAIN_DB: &[u8] = b"ayva_db_v1";
pub const DOMAIN_VAULT: &[u8] = b"ayva_vault_v1";
pub const DOMAIN_HMAC: &[u8] = b"ayva_hmac_v1";

#[derive(Debug)]
pub enum HkdfError {
    ExpansionError(String),
}

impl std::fmt::Display for HkdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExpansionError(s) => write!(f, "HKDF expansion error: {}", s),
        }
    }
}

impl std::error::Error for HkdfError {}

/// Derives a 256-bit domain-separated subkey from the master key using RFC 5869 HKDF-SHA256
pub fn derive_subkey(
    master_key: &KeyBuffer32,
    domain_info: &[u8],
    salt: Option<&[u8]>,
) -> Result<KeyBuffer32, HkdfError> {
    let hk = Hkdf::<Sha256>::new(salt, master_key.as_slice());
    let mut okm = [0u8; 32];

    hk.expand(domain_info, &mut okm)
        .map_err(|e| HkdfError::ExpansionError(e.to_string()))?;

    let subkey = KeyBuffer32::new(okm);
    okm.zeroize();

    Ok(subkey)
}

/// Derives the dedicated SQLCipher database encryption key
pub fn derive_db_key(master_key: &KeyBuffer32) -> Result<KeyBuffer32, HkdfError> {
    derive_subkey(master_key, DOMAIN_DB, None)
}

/// Derives the per-note XChaCha20-Poly1305 envelope encryption key
pub fn derive_vault_key(master_key: &KeyBuffer32) -> Result<KeyBuffer32, HkdfError> {
    derive_subkey(master_key, DOMAIN_VAULT, None)
}

/// Derives the payload integrity authentication HMAC key
pub fn derive_hmac_key(master_key: &KeyBuffer32) -> Result<KeyBuffer32, HkdfError> {
    derive_subkey(master_key, DOMAIN_HMAC, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_hkdf_domain_separation_independence() {
        let master = KeyBuffer32::new([0x33; 32]);

        let db_key = derive_db_key(&master).expect("db key derivation");
        let vault_key = derive_vault_key(&master).expect("vault key derivation");
        let hmac_key = derive_hmac_key(&master).expect("hmac key derivation");

        // Cryptographic domain separation guarantees all derived keys are distinct
        assert!(!bool::from(db_key.ct_eq(&vault_key)));
        assert!(!bool::from(db_key.ct_eq(&hmac_key)));
        assert!(!bool::from(vault_key.ct_eq(&hmac_key)));
    }

    #[test]
    fn test_hkdf_determinism() {
        let master = KeyBuffer32::new([0x77; 32]);

        let k1 = derive_vault_key(&master).unwrap();
        let k2 = derive_vault_key(&master).unwrap();

        assert!(bool::from(k1.ct_eq(&k2)));
    }
}
