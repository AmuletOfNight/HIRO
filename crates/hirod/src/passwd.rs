//! Account password verification for the sealed keyring password.
//!
//! `hirod` runs as root, so it can read the shadow database and confirm
//! that the TPM-sealed login password still matches the account before
//! releasing it to `pam_hiro.so`. This is what makes the keyring feature
//! safe: if the user changes their password and forgets to re-run
//! `hiro keyring set`, face login keeps working (the stale password is
//! simply never released) instead of failing.
//!
//! Verification uses `crypt_r(3)` from libxcrypt/libcrypt against the hash
//! in `/etc/shadow` (thread-safe: each call gets its own `crypt_data`).
//! The module is linked with `-lcrypt`; on Debian/Ubuntu that is provided
//! by the base `libcrypt1` at runtime and `libcrypt-dev` at build.

use std::ffi::{CStr, CString};

/// Scratch space for `crypt_r`. libxcrypt's `struct crypt_data` is exactly
/// 32768 bytes (output + reserved + initialized flag + internal scratch);
/// a zeroed buffer of that size satisfies the "set initialized to 0 before
/// first use" contract. Per-call allocation makes verification safe for the
/// daemon's concurrent connections — plain `crypt(3)` is not thread-safe on
/// all glibc builds.
#[repr(C, align(16))]
struct CryptDataBuffer([u8; 32768]);

#[link(name = "crypt")]
extern "C" {
    /// Compute the crypt(3) hash of `phrase` under `setting`, writing the
    /// result into the caller-provided `data` area. Returns a pointer into
    /// `data`, or NULL on error. Thread-safe: no shared state.
    fn crypt_r(
        phrase: *const libc::c_char,
        setting: *const libc::c_char,
        data: *mut libc::c_void,
    ) -> *mut libc::c_char;
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a plaintext password against a crypt(3)-format hash.
///
/// Pure function, used both by [`verify_password`] and directly in tests.
pub fn verify_with_hash(password: &str, hash: &str) -> bool {
    let Ok(cpassword) = CString::new(password) else {
        return false;
    };
    let Ok(chash) = CString::new(hash) else {
        return false;
    };
    let mut buf = CryptDataBuffer([0u8; 32768]);
    // SAFETY: `buf` is zeroed (so `initialized` is 0 as required on first
    // use) and large enough for any `struct crypt_data`; the C strings are
    // valid NUL-terminated input. The returned pointer lives inside `buf`.
    let result = unsafe {
        crypt_r(
            cpassword.as_ptr(),
            chash.as_ptr(),
            (&mut buf as *mut CryptDataBuffer).cast(),
        )
    };
    if result.is_null() {
        return false;
    }
    // SAFETY: on success `result` points at a NUL-terminated hash string
    // inside `buf`, which is still alive and not mutated.
    let computed = unsafe { CStr::from_ptr(result) };
    constant_time_eq(computed.to_bytes(), hash.as_bytes())
}

/// Read the password hash for `user` from `/etc/shadow` (root only).
///
/// Returns `None` for unknown users, locked accounts (hash `!`/`*`), and
/// any environment where shadow is unreadable. Uses the reentrant
/// `getspnam_r(3)` so concurrent daemon connections cannot race on a static
/// buffer.
pub fn shadow_hash(user: &str) -> Option<String> {
    let cuser = CString::new(user).ok()?;
    // SAFETY: `spwd` and the scratch buffer outlive the call, and
    // `result` is only dereferenced when non-null (success).
    let mut spwd: libc::spwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::spwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getspnam_r(
            cuser.as_ptr(),
            &mut spwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `result` points at a `struct spwd` whose `sp_pwdp` is a
    // NUL-terminated string valid until the next shadow call.
    unsafe {
        CStr::from_ptr((*result).sp_pwdp)
            .to_str()
            .ok()
            .map(str::to_owned)
    }
}

/// Whether `password` is the current login password for `user`.
///
/// A hash that is empty, or starts with `!` or `*`, marks a locked or
/// password-less account, which never verifies.
pub fn verify_password(user: &str, password: &str) -> bool {
    let Some(hash) = shadow_hash(user) else {
        return false;
    };
    if hash.is_empty() || hash.starts_with('!') || hash.starts_with('*') {
        return false;
    }
    verify_with_hash(password, &hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha512crypt of "hunter2" with salt "testsalt" (openssl passwd -6).
    const HASH: &str = "$6$testsalt$ehrqOiQRn2f7nCvA/LgwTY1odMW9hjQ/GS8KC7ztGNzzC8hmzy8/g/pV7Ryg5gmQx7Wa1u13rOGLJIS5QQGcQ/";

    #[test]
    fn crypt_verifies_correct_password() {
        assert!(verify_with_hash("hunter2", HASH));
    }

    #[test]
    fn crypt_rejects_wrong_password() {
        assert!(!verify_with_hash("hunter3", HASH));
        assert!(!verify_with_hash("", HASH));
    }

    #[test]
    fn locked_and_short_hashes_never_verify() {
        assert!(!verify_with_hash("hunter2", "!$6$testsalt$xyz"));
        assert!(!verify_with_hash("hunter2", "*"));
        assert!(!verify_with_hash("hunter2", ""));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
