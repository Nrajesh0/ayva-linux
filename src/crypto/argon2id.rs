/*
 * Ayva for Fedora GNOME 44+
 * Argon2id Key Derivation Function (RFC 9106)
 *
 * Provides desktop-grade memory-hard key derivation to protect
 * user PINs/passcodes against GPU, ASIC, and FPGA brute-force attacks.
 */

use crate::crypto::memlock::KeyBuffer32;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum Argon2Error {
    ParamError(String),
    DerivationError(String),
}

impl std::fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParamError(s) => write!(f, "Argon2 parameter error: {}", s),
            Self::DerivationError(s) => write!(f, "Argon2 derivation error: {}", s),
        }
    }
}

impl std::error::Error for Argon2Error {}

/// Parameters for Argon2id derivation
#[derive(Clone, Copy, Debug)]
pub struct Argon2Config {
    pub m_cost: u32, // Memory size in KiB
    pub t_cost: u32, // Number of iterations
    pub p_cost: u32, // Parallelism degree
}

impl Argon2Config {
    /// OWASP-recommended desktop profile (64 MB RAM, 3 iterations, 4 threads)
    pub const DESKTOP: Self = Self {
        m_cost: 64 * 1024, // 65536 KiB = 64 MiB
        t_cost: 3,
        p_cost: 4,
    };

    /// Fast profile for automated test suites
    pub const TEST: Self = Self {
        m_cost: 1024, // 1 MiB
        t_cost: 1,
        p_cost: 1,
    };
}

/// Generates a 32-byte cryptographically secure random salt using OS entropy
pub fn generate_salt_32() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit (32-byte) Master Vault Key from a passcode and salt
/// using Argon2id. The resulting buffer is wrapped in KeyBuffer32 with ZeroizeOnDrop.
pub fn derive_master_key(
    passcode: &[u8],
    salt: &[u8],
    config: Argon2Config,
) -> Result<KeyBuffer32, Argon2Error> {
    let params = Params::new(config.m_cost, config.t_cost, config.p_cost, Some(32))
        .map_err(|e| Argon2Error::ParamError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passcode, salt, &mut output)
        .map_err(|e| Argon2Error::DerivationError(e.to_string()))?;

    let key = KeyBuffer32::new(output);
    output.zeroize();

    Ok(key)
}

/// Verifies whether candidate bytes derive to the expected key buffer in constant-time
pub fn verify_key(
    candidate: &[u8],
    salt: &[u8],
    expected_key: &KeyBuffer32,
    config: Argon2Config,
) -> Result<bool, Argon2Error> {
    let derived = derive_master_key(candidate, salt, config)?;
    let is_match = bool::from(derived.ct_eq(expected_key));
    Ok(is_match)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derivation_determinism() {
        let pin = b"123456";
        let salt = [7u8; 32];
        let config = Argon2Config::TEST;

        let key1 = derive_master_key(pin, &salt, config).expect("derivation failed");
        let key2 = derive_master_key(pin, &salt, config).expect("derivation failed");

        assert!(bool::from(key1.ct_eq(&key2)), "Same PIN and salt must yield identical master key");
        assert_ne!(key1.bytes, [0u8; 32], "Derived key must not be all zeros");
    }

    #[test]
    fn test_argon2id_different_passcode_yields_different_key() {
        let salt = [42u8; 32];
        let config = Argon2Config::TEST;

        let key1 = derive_master_key(b"123456", &salt, config).unwrap();
        let key2 = derive_master_key(b"654321", &salt, config).unwrap();

        assert!(!bool::from(key1.ct_eq(&key2)), "Different PINs must derive different keys");
    }

    #[test]
    fn test_argon2id_salt_generation_uniqueness() {
        let salt1 = generate_salt_32();
        let salt2 = generate_salt_32();
        assert_ne!(salt1, salt2, "Subsequent salts must be unique");
    }

    #[test]
    fn test_verify_key_constant_time() {
        let pin = b"correct_vault_pin";
        let salt = generate_salt_32();
        let config = Argon2Config::TEST;

        let master_key = derive_master_key(pin, &salt, config).unwrap();

        assert!(verify_key(pin, &salt, &master_key, config).unwrap());
        assert!(!verify_key(b"wrong_pin", &salt, &master_key, config).unwrap());
    }
}
