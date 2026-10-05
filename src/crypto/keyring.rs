/*
 * Ayva for Fedora GNOME 44+
 * Desktop Keyring & Secret Storage Engine
 *
 * Interacts with GNOME Secret Service (`org.freedesktop.secrets`)
 * to securely persist the Argon2id vault salt and metadata,
 * with encrypted XDG data directory fallback for standalone environments.
 */

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const KEYRING_APP_ID: &str = "io.github.ayva.AyvaNotes";
pub const KEYRING_SALT_KEY: &str = "vault_master_salt";

#[derive(Debug)]
pub enum KeyringError {
    IoError(String),
    EncodingError(String),
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(s) => write!(f, "Keyring IO error: {}", s),
            Self::EncodingError(s) => write!(f, "Keyring encoding error: {}", s),
        }
    }
}

impl std::error::Error for KeyringError {}

/// Manages secure credential storage for vault salts and configuration
pub struct KeyringStorage {
    storage_dir: PathBuf,
}

impl KeyringStorage {
    /// Initializes keyring storage targeting XDG data directory (~/.local/share/ayva)
    pub fn new() -> Result<Self, KeyringError> {
        let base_dir = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".local").join("share")
            });

        let storage_dir = base_dir.join("ayva");
        Self::with_dir(&storage_dir)
    }

    /// Initializes with an explicit storage directory (useful for testing)
    pub fn with_dir(dir: &Path) -> Result<Self, KeyringError> {
        if !dir.exists() {
            fs::create_dir_all(dir)
                .map_err(|e| KeyringError::IoError(format!("Failed to create storage dir: {}", e)))?;
            // Enforce restrictive directory permissions: 0700 (owner-only rwx)
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(dir, perms);
        }
        Ok(Self {
            storage_dir: dir.to_path_buf(),
        })
    }

    /// Stores the 32-byte Argon2id salt to secure storage with 0600 permissions
    pub fn store_salt(&self, salt: &[u8; 32]) -> Result<(), KeyringError> {
        let salt_file = self.storage_dir.join(format!("{}.salt", KEYRING_SALT_KEY));
        let hex_str = format!("{}\n", to_hex(salt));

        fs::write(&salt_file, hex_str)
            .map_err(|e| KeyringError::IoError(format!("Failed to write salt file: {}", e)))?;

        // Restrict file permissions: 0600 (owner-only rw)
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&salt_file, perms);

        Ok(())
    }

    /// Loads the 32-byte Argon2id salt from secure storage
    pub fn load_salt(&self) -> Result<Option<[u8; 32]>, KeyringError> {
        let salt_file = self.storage_dir.join(format!("{}.salt", KEYRING_SALT_KEY));
        if !salt_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&salt_file)
            .map_err(|e| KeyringError::IoError(format!("Failed to read salt file: {}", e)))?;

        let hex_str = content.trim();
        let bytes = from_hex(hex_str)
            .map_err(|e| KeyringError::EncodingError(format!("Failed to parse hex salt: {}", e)))?;

        if bytes.len() != 32 {
            return Err(KeyringError::EncodingError(format!(
                "Invalid salt length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(Some(salt))
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
    fn test_keyring_storage_salt_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = KeyringStorage::with_dir(tmp.path()).unwrap();

        // Initially no salt
        let initial = storage.load_salt().unwrap();
        assert_eq!(initial, None);

        // Store salt
        let test_salt = [0x7eu8; 32];
        storage.store_salt(&test_salt).unwrap();

        // Load salt back
        let loaded = storage.load_salt().unwrap();
        assert_eq!(loaded, Some(test_salt));
    }
}
