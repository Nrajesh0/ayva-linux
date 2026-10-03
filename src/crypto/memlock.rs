/*
 * Ayva for Fedora GNOME 44+
 * Low-Level Linux Process & Memory Hardening Engine
 *
 * Implements:
 * 1. PR_SET_DUMPABLE=0 via prctl(2) (blocks systemd-coredump and ptrace memory scraping)
 * 2. libc::mlock(2) page-locking (prevents sensitive keys from leaking to zram/swap)
 * 3. Constant-time operations and zeroize-on-drop byte memory guarantees
 */

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Disables process coredumps and forbids unprivileged ptrace attachments
/// from inspecting memory.
///
/// On Fedora GNOME, unhandled process crashes trigger `systemd-coredump`,
/// which by default saves full process memory dumps to disk. Calling
/// `prctl(PR_SET_DUMPABLE, 0)` instructs the Linux kernel to refuse coredump
/// creation and deny ptrace attach calls.
pub fn disable_core_dumps() -> Result<(), String> {
    unsafe {
        let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to set PR_SET_DUMPABLE to 0: {}", err));
        }
    }
    Ok(())
}

/// Checks the current process Dumpable flag via prctl(PR_GET_DUMPABLE).
/// Returns true if the process is dumpable (insecure), false if dumpable is 0 (hardened).
pub fn is_dumpable() -> Result<bool, String> {
    unsafe {
        let ret = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0);
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to query PR_GET_DUMPABLE: {}", err));
        }
        Ok(ret != 0)
    }
}

/// A heap-allocated memory container pinned in physical RAM using `libc::mlock`.
///
/// Ensures the underlying bytes are:
/// 1. Pinned in RAM (never paged out to disk swap or zram-swap)
/// 2. Overwritten with zeros immediately upon drop (`Zeroize`)
/// 3. Safely unpinned upon deallocation (`libc::munlock`)
#[derive(Debug)]
pub struct LockedMemory<T: Zeroize> {
    data: Box<T>,
    is_locked: bool,
}

impl<T: Zeroize> LockedMemory<T> {
    /// Allocates `value` on the heap and locks the underlying memory page into RAM.
    pub fn new(value: T) -> Result<Self, String> {
        let mut boxed = Box::new(value);
        let ptr = boxed.as_mut() as *mut T as *const libc::c_void;
        let len = std::mem::size_of::<T>();

        if len > 0 {
            unsafe {
                let ret = libc::mlock(ptr, len);
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!("mlock failed (size: {} bytes): {}", len, err));
                }
            }
        }

        Ok(Self {
            data: boxed,
            is_locked: true,
        })
    }

    /// Creates a locked memory block, with graceful fallback to standard Zeroize heap allocation
    /// if RLIMIT_MEMLOCK limit is encountered.
    pub fn new_lenient(value: T) -> Self {
        let mut boxed = Box::new(value);
        let ptr = boxed.as_mut() as *mut T as *const libc::c_void;
        let len = std::mem::size_of::<T>();
        let mut is_locked = false;

        if len > 0 {
            unsafe {
                if libc::mlock(ptr, len) == 0 {
                    is_locked = true;
                }
            }
        }

        Self {
            data: boxed,
            is_locked,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.is_locked
    }
}

impl<T: Zeroize> Deref for LockedMemory<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for LockedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for LockedMemory<T> {
    fn drop(&mut self) {
        // Step 1: Zeroize sensitive memory contents
        self.data.zeroize();

        // Step 2: Unlock physical memory page if previously locked
        if self.is_locked {
            let ptr = self.data.as_mut() as *mut T as *const libc::c_void;
            let len = std::mem::size_of::<T>();
            if len > 0 {
                unsafe {
                    libc::munlock(ptr, len);
                }
            }
        }
    }
}

/// A zeroized, fixed-size sensitive key buffer (32 bytes = 256 bits)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyBuffer32 {
    pub bytes: [u8; 32],
}

impl KeyBuffer32 {
    pub fn new(data: [u8; 32]) -> Self {
        Self { bytes: data }
    }

    pub fn zero() -> Self {
        Self { bytes: [0u8; 32] }
    }

    pub fn as_slice(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl subtle::ConstantTimeEq for KeyBuffer32 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_disable_core_dumps() {
        let res = disable_core_dumps();
        assert!(res.is_ok(), "Setting PR_SET_DUMPABLE to 0 must succeed");

        let dumpable = is_dumpable();
        assert!(dumpable.is_ok());
        assert_eq!(dumpable.unwrap(), false, "Process must report dumpable = 0");
    }

    #[test]
    fn test_locked_memory_lifecycle() {
        let secret = [42u8; 32];
        let mut locked = LockedMemory::new_lenient(secret);
        assert_eq!(locked[0], 42);
        assert_eq!(locked[31], 42);

        locked[0] = 99;
        assert_eq!(locked[0], 99);
        // Memory drops and zeroizes on scope exit
    }

    #[test]
    fn test_key_buffer_constant_time_equality() {
        let key1 = KeyBuffer32::new([7u8; 32]);
        let key2 = KeyBuffer32::new([7u8; 32]);
        let mut key3_bytes = [7u8; 32];
        key3_bytes[31] = 8;
        let key3 = KeyBuffer32::new(key3_bytes);

        assert!(bool::from(key1.ct_eq(&key2)));
        assert!(!bool::from(key1.ct_eq(&key3)));
    }
}
