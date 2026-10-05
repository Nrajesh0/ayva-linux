# Ayva Linux - Batch Implementation Tracker & Roadmap

**Target Platform**: Fedora GNOME 44+ (Wayland, SELinux, Flatpak)  
**Project Path**: `/home/rajesh/.gemini/antigravity/scratch/ayva-linux`  
**Git Repository**: `https://github.com/Nrajesh0/ayva-linux`  
**Source Android Repository**: `https://github.com/Nrajesh0/Ayva`  

---

## Batch Status Summary

| Batch # | Batch Name | Status | Verified / Tests Passing |
|:---:|:---|:---:|:---:|
| **Batch 1** | **Project Scaffold & Process Memory Hardening** | **COMPLETED** | ✅ 6/6 tests passing (`prctl`, `mlock`, `zeroize`) |
| **Batch 2** | **Cryptographic Core Engine (Argon2id, HKDF, XChaCha20, BIP-39)** | **COMPLETED** | ✅ 23/23 tests passing (Argon2id, HKDF, XChaCha20-Poly1305, BIP-39 recovery) |
| **Batch 3** | **Smart Date & NLP Todo Parser (`smart_date.rs`)** | **PENDING APPROVAL** | Next up |
| **Batch 4** | **SQLCipher Database Layer** | Pending | - |
| **Batch 5** | **Vault Security Manager & Monotonic Lockout Engine** | Pending | - |
| **Batch 6** | **Ayva Midnight Theme & Design System (CSS Tokens)** | Pending | - |
| **Batch 7** | **Main Application Shell & Navigation (Libadwaita)** | Pending | - |
| **Batch 8** | **Notes Grid & Tinted Cards UI** | Pending | - |
| **Batch 9** | **Notesnook-Grade Rich Block Editor** | Pending | - |
| **Batch 10**| **PIN Unlock, Vault Setup & Recovery Dialogs** | Pending | - |
| **Batch 11**| **Todo List & Smart NLP Composer** | Pending | - |
| **Batch 12**| **GNOME D-Bus Session & ScreenSaver Auto-Lock** | Pending | - |
| **Batch 13**| **Fedora Packaging & Flatpak Sandbox (`--unshare=network`)**| Pending | - |

---

## Detailed Batch Logs

### Batch 1: Project Scaffold & Process Memory Hardening (COMPLETED)
* **Date Completed**: 2026-10-03
* **Artifacts Created**:
  * `Cargo.toml`: Root dependencies configured (libc, zeroize, subtle, argon2, chacha20poly1305, hkdf, sha2, bip39, rusqlite, serde, regex, chrono).
  * `src/crypto/memlock.rs`:
    * `disable_core_dumps()`: Kernel-level `prctl(PR_SET_DUMPABLE, 0)`.
    * `is_dumpable()`: Kernel query via `prctl(PR_GET_DUMPABLE)`.
    * `LockedMemory<T>`: RAM page pinning via `libc::mlock()`, `ZeroizeOnDrop` memory zeroing.
    * `KeyBuffer32`: Constant-time 256-bit key comparison with `subtle::ConstantTimeEq`.
  * `src/lib.rs` & `src/main.rs`: Entry point and library export.
  * `tests/security_tests.rs`: Integration tests for process hardening.
* **Verification**:
  * `cargo test`: 6 passed, 0 failed.
  * `cargo run`: Successfully verifies dumpable is DISABLED.

---

### Batch 2: Cryptographic Core Engine (COMPLETED)
* **Date Completed**: 2026-10-05
* **Artifacts Created**:
  * `src/crypto/argon2id.rs`:
    * RFC 9106 Argon2id memory-hard KDF.
    * Profiles for OWASP Desktop (`m=64MB, t=3, p=4`) and test execution (`m=1MB, t=1, p=1`).
    * Constant-time key comparison and 32-byte OS random salt generation.
  * `src/crypto/hkdf.rs`:
    * RFC 5869 HMAC Extract-and-Expand KDF.
    * Domain separation labels: `"ayva_db_v1"`, `"ayva_vault_v1"`, `"ayva_hmac_v1"`.
  * `src/crypto/envelope.rs`:
    * `ENC_VAULT_V2` format with XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit Poly1305 tag).
    * Typed `DecryptionResult` (Success, AuthFailed, Malformed).
    * Tamper and bit-flip detection.
  * `src/crypto/mnemonic.rs`:
    * BIP-39 12-word English mnemonic generation via 128-bit OsRng entropy.
    * PBKDF2-HMAC-SHA512 seed derivation + HKDF recovery key.
    * Emergency vault restoration from recovery envelope.
  * `src/crypto/keyring.rs`:
    * GNOME Secret Service / XDG secure file persistence (`0600` permissions) for salt and metadata.
  * `tests/crypto_tests.rs`:
    * Full vault lifecycle integration test.
    * Emergency forgotten-PIN 12-word restoration integration test.
* **Verification**:
  * `cargo test`: 23 passed, 0 failed.

---

### Instructions for Any Fresh Session:
If resuming in a new conversation:
1. Open working directory `/home/rajesh/.gemini/antigravity/scratch/ayva-linux`.
2. Inspect this `PROGRESS.md` file and `git log --oneline`.
3. Check the next pending batch.
4. Execute strictly one batch at a time with full verification before proceeding.
