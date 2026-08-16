//! Encryption key management for face templates.
//!
//! HIRO never stores embeddings in plaintext. The daemon uses a
//! [`KeyManager`] to seal (encrypt) templates before they reach SQLite and
//! unseal (decrypt) them for in-memory matching only.
//!
//! Two implementations exist:
//!
//! * [`SoftwareKeyManager`] — a random 256-bit AES-GCM data key kept in a
//!   root-only keyfile (`/var/lib/hiro/hiro.key` by default). Always
//!   available.
//! * [`TpmKeyManager`] (feature `tpm`) — the same data key, sealed under
//!   a TPM 2.0 primary key so the plaintext key never rests on disk and
//!   unsealing only succeeds on this machine's TPM.

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hiro_core::{CoreError, Result};

mod software;
#[cfg(feature = "tpm")]
mod tpm;

pub use software::SoftwareKeyManager;
#[cfg(feature = "tpm")]
pub use tpm::TpmKeyManager;

const NONCE_LEN: usize = 12;

/// Seal/unseal interface for template ciphertext.
///
/// The wire format produced by [`KeyManager::seal`] is
/// `nonce(12) || AES-256-GCM ciphertext`, so implementations only need to
/// protect the data key; the AEAD construction is shared.
pub trait KeyManager: Send + Sync {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    /// Whether a hardware TPM backs the data key.
    fn tpm_available(&self) -> bool;
    fn kind(&self) -> &'static str;
}

/// Build the key manager described by `key_path`.
///
/// With the `tpm` feature enabled, a TPM-sealed keyfile is detected by its
/// blob format; software-format keyfiles keep working. Without the feature
/// (or without a TPM), the software manager is used.
pub fn load(key_path: &Path) -> Result<Box<dyn KeyManager>> {
    #[cfg(feature = "tpm")]
    {
        if let Ok(blob) = std::fs::read(key_path) {
            if !blob.is_empty() && blob[0] == tpm::SEALED_VERSION_BYTE {
                let km = TpmKeyManager::load(key_path)?;
                return Ok(Box::new(km));
            }
        }
    }
    let km = SoftwareKeyManager::load(key_path)?;
    Ok(Box::new(km))
}

/// Create the key manager described by `key_path`, generating a fresh key.
/// Returns an error if the key already exists.
///
/// With the `tpm` feature enabled, tries the TPM-backed manager first and
/// falls back to the software manager when no TPM 2.0 device is present.
pub fn create(key_path: &Path) -> Result<Box<dyn KeyManager>> {
    #[cfg(feature = "tpm")]
    match TpmKeyManager::create(key_path) {
        Ok(km) => return Ok(Box::new(km)),
        Err(e) => log::warn!("TPM unavailable, falling back to software key management: {e}"),
    }
    Ok(Box::new(SoftwareKeyManager::create(key_path)?))
}

/// AEAD helpers shared by all key managers.
pub(crate) fn aead_seal(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::internal("AES-GCM encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn aead_unseal(key_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() <= NONCE_LEN {
        return Err(CoreError::invalid("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let (nonce_bytes, ct) = ciphertext.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| CoreError::invalid("AES-GCM decryption failed: wrong key or tampered data"))
}

/// Fill `buf` with cryptographically secure randomness from the OS.
pub(crate) fn fill_random(buf: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom must exist");
    f.read_exact(buf).expect("failed to read from /dev/urandom");
}

/// Shared helper for keyfile managers.
pub(crate) fn read_keyfile(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .map_err(|e| CoreError::io(format!("cannot read keyfile {}: {e}", path.display())))?;
    if data.len() != 32 {
        return Err(CoreError::config(format!(
            "keyfile {} must contain exactly 32 bytes, found {}",
            path.display(),
            data.len()
        )));
    }
    Ok(data)
}

/// Shared helper for keyfile managers.
pub(crate) fn write_keyfile(path: &Path, key_bytes: &[u8]) -> Result<()> {
    let parent: PathBuf = path.parent().map(Path::to_path_buf).ok_or_else(|| {
        CoreError::io(format!(
            "keyfile {} has no parent directory",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(&parent)
        .map_err(|e| CoreError::io(format!("cannot create {}: {e}", parent.display())))?;

    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true).mode(0o600);
    match opts.open(path) {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(key_bytes).map_err(|e| {
                CoreError::io(format!("cannot write keyfile {}: {e}", path.display()))
            })?;
            f.sync_all().map_err(|e| {
                CoreError::io(format!("cannot sync keyfile {}: {e}", path.display()))
            })?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CoreError::config(format!(
                "keyfile already exists: {}",
                path.display()
            )));
        }
        Err(e) => {
            return Err(CoreError::io(format!(
                "cannot create keyfile {}: {e}",
                path.display()
            )))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip() {
        let key = [7u8; 32];
        let msg = b"hello, templates";
        let ct = aead_seal(&key, msg).unwrap();
        assert_eq!(ct.len(), NONCE_LEN + msg.len() + 16);
        assert_eq!(aead_unseal(&key, &ct).unwrap(), msg);
    }

    #[test]
    fn aead_tamper_detected() {
        let key = [7u8; 32];
        let mut ct = aead_seal(&key, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(aead_unseal(&key, &ct).is_err());
    }

    #[test]
    fn aead_wrong_key_detected() {
        let ct = aead_seal(&[1u8; 32], b"secret").unwrap();
        assert!(aead_unseal(&[2u8; 32], &ct).is_err());
    }

    #[test]
    fn aead_short_input_rejected() {
        assert!(aead_unseal(&[1u8; 32], b"tiny").is_err());
    }

    #[test]
    fn software_manager_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hiro.key");
        let km = SoftwareKeyManager::create(&path).unwrap();
        assert!(!km.tpm_available());
        let ct = km.seal(b"template-bytes").unwrap();
        assert_eq!(km.unseal(&ct).unwrap(), b"template-bytes");

        let km2 = SoftwareKeyManager::load(&path).unwrap();
        assert_eq!(km2.unseal(&ct).unwrap(), b"template-bytes");
    }

    #[test]
    fn software_manager_refuses_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hiro.key");
        SoftwareKeyManager::create(&path).unwrap();
        assert!(SoftwareKeyManager::create(&path).is_err());
    }

    #[test]
    fn software_manager_rejects_bad_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hiro.key");
        std::fs::write(&path, b"short").unwrap();
        assert!(SoftwareKeyManager::load(&path).is_err());
    }
}
