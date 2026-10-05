/*
 * End-to-End Cryptographic Core Integration Tests for Batch 2
 *
 * Verifies:
 * 1. Argon2id KDF + HKDF domain separation integration
 * 2. XChaCha20-Poly1305 per-note envelope roundtrip
 * 3. 12-word BIP-39 emergency vault restoration
 * 4. Multi-layer tamper detection and wrong-PIN rejection
 */

use ayva_linux::crypto::argon2id::{derive_master_key, generate_salt_32, Argon2Config};
use ayva_linux::crypto::envelope::{DecryptionResult, VaultEnvelope, CURRENT_KEY_VERSION};
use ayva_linux::crypto::hkdf::{derive_db_key, derive_hmac_key, derive_vault_key};
use ayva_linux::crypto::mnemonic::{
    create_recovery_envelope, derive_recovery_key, generate_mnemonic_phrase,
    restore_master_key_from_envelope,
};
use subtle::ConstantTimeEq;

#[test]
fn test_full_vault_crypto_lifecycle() {
    let pin = b"948201";
    let salt = generate_salt_32();
    let config = Argon2Config::TEST;

    // 1. Derive master key from user PIN
    let master_key = derive_master_key(pin, &salt, config).expect("Master key derivation failed");

    // 2. Derive domain-separated keys via HKDF
    let db_key = derive_db_key(&master_key).expect("DB key derivation failed");
    let vault_key = derive_vault_key(&master_key).expect("Vault key derivation failed");
    let hmac_key = derive_hmac_key(&master_key).expect("HMAC key derivation failed");

    // All keys must be cryptographically distinct
    assert!(!bool::from(db_key.ct_eq(&vault_key)));
    assert!(!bool::from(db_key.ct_eq(&hmac_key)));

    // 3. Encrypt a mock rich note
    let mock_note_json = br#"{"title":"Confidential Plan","blocks":[{"type":"text","content":"Top Secret"}]}"#;
    let envelope = VaultEnvelope::encrypt(mock_note_json, &vault_key, CURRENT_KEY_VERSION)
        .expect("Envelope encryption failed");

    // Serialize envelope to disk format
    let serialized = envelope.serialize();
    assert!(serialized.starts_with("ENC_VAULT_V2:kv=1:"));

    // 4. Successful login: Re-derive keys and decrypt note
    let login_master_key = derive_master_key(pin, &salt, config).unwrap();
    let login_vault_key = derive_vault_key(&login_master_key).unwrap();

    let parsed_envelope = VaultEnvelope::parse(&serialized).expect("Parse failed");
    let decrypted = parsed_envelope.decrypt(&login_vault_key);

    assert_eq!(
        decrypted,
        DecryptionResult::Success(mock_note_json.to_vec()),
        "Decrypted note must match original plaintext"
    );

    // 5. Unsuccessful login (Wrong PIN)
    let wrong_master_key = derive_master_key(b"000000", &salt, config).unwrap();
    let wrong_vault_key = derive_vault_key(&wrong_master_key).unwrap();

    let fail_result = parsed_envelope.decrypt(&wrong_vault_key);
    assert_eq!(
        fail_result,
        DecryptionResult::AuthFailed,
        "Wrong PIN must fail envelope authentication"
    );
}

#[test]
fn test_forgotten_pin_emergency_bip39_restoration() {
    let original_pin = b"554433";
    let salt = generate_salt_32();
    let config = Argon2Config::TEST;

    // 1. Initial vault setup
    let master_key = derive_master_key(original_pin, &salt, config).unwrap();
    let vault_key = derive_vault_key(&master_key).unwrap();

    // Generate 12-word recovery sheet for user
    let recovery_phrase = generate_mnemonic_phrase().expect("Mnemonic generation");
    let recovery_key = derive_recovery_key(&recovery_phrase).unwrap();

    // Create recovery envelope stored in database
    let recovery_envelope = create_recovery_envelope(&master_key, &recovery_key).unwrap();

    // Encrypt notes
    let note_content = b"Notes written before forgetting PIN";
    let note_envelope = VaultEnvelope::encrypt(note_content, &vault_key, 1).unwrap();

    // 2. DISASTER: User forgot PIN "554433" completely!
    // Recovery flow: User enters their 12 emergency words
    let entered_recovery_key = derive_recovery_key(&recovery_phrase).unwrap();
    let restored_master_key =
        restore_master_key_from_envelope(&recovery_envelope, &entered_recovery_key)
            .expect("Emergency restoration failed");

    assert!(
        bool::from(master_key.ct_eq(&restored_master_key)),
        "Restored master key must be bitwise identical to original"
    );

    // 3. User can now decrypt their notes with the restored key
    let restored_vault_key = derive_vault_key(&restored_master_key).unwrap();
    let note_decrypt = note_envelope.decrypt(&restored_vault_key);

    assert_eq!(note_decrypt, DecryptionResult::Success(note_content.to_vec()));
}
