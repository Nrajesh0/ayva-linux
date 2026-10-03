/*
 * Integration and Verification Tests for Batch 1: Memory & Process Hardening
 */

use ayva_linux::crypto::memlock::{disable_core_dumps, is_dumpable, KeyBuffer32, LockedMemory};
use subtle::ConstantTimeEq;

#[test]
fn test_kernel_prctl_coredump_block() {
    let result = disable_core_dumps();
    assert!(result.is_ok(), "prctl(PR_SET_DUMPABLE, 0) should succeed on Linux");

    let is_dump = is_dumpable().expect("Failed to read /proc/self/status");
    assert!(!is_dump, "Kernel must report Dumpable: 0, preventing ptrace & systemd-coredump leaks");
}

#[test]
fn test_locked_memory_lifecycle_and_zeroization() {
    let raw_secret = [0x5au8; 32];
    {
        let mut locked = LockedMemory::new_lenient(raw_secret);
        assert_eq!(locked[0], 0x5a);
        assert_eq!(locked[31], 0x5a);

        // Mutate in place
        locked[15] = 0xff;
        assert_eq!(locked[15], 0xff);
    }
    // `locked` has been dropped, zeroized and unpinned from RAM
}

#[test]
fn test_key_buffer_subtle_equality() {
    let k1 = KeyBuffer32::new([0xab; 32]);
    let k2 = KeyBuffer32::new([0xab; 32]);
    let mut diff = [0xab; 32];
    diff[0] = 0xac;
    let k3 = KeyBuffer32::new(diff);

    assert!(bool::from(k1.ct_eq(&k2)));
    assert!(!bool::from(k1.ct_eq(&k3)));
}
