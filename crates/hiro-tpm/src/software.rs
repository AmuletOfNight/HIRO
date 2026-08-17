//! Software (no-TPM) key manager: a random 256-bit data key in a
//! root-only keyfile, used directly for AES-256-GCM.

use std::path::Path;

use hiro_core::{CoreError, Result};
use zeroize::Zeroizing;

use crate::{aead_seal, aead_unseal, fill_random, read_keyfile, write_keyfile, KeyManager};

pub struct SoftwareKeyManager {
    /// The data key. Wrapped in `Zeroizing` so the in-memory key is wiped
    /// when the manager is dropped.
    key: Zeroizing<[u8; 32]>,
}

impl SoftwareKeyManager {
    /// Load the data key from `path` (creating nothing).
    pub fn load(path: &Path) -> Result<Self> {
        let mut data = read_keyfile(path)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        // Zeroize the temporary copy before it is freed.
        data.fill(0);
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// Generate a fresh data key and write it to `path` with mode 0600.
    /// Fails if the file already exists.
    pub fn create(path: &Path) -> Result<Self> {
        let mut key = [0u8; 32];
        fill_random(&mut key);
        write_keyfile(path, &key)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// Build directly from a known key (tests, import flows).
    pub fn from_key(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }
}

impl KeyManager for SoftwareKeyManager {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        aead_seal(&self.key[..], aad, plaintext)
    }

    fn unseal(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        aead_unseal(&self.key[..], aad, ciphertext)
    }

    fn tpm_available(&self) -> bool {
        false
    }

    fn kind(&self) -> &'static str {
        "software"
    }
}

/// Convenience constructor that fails loudly instead of panicking, for
/// call sites that must not use `expect` in library code paths.
#[allow(dead_code)]
pub(crate) fn validate_key_length(key: &[u8]) -> Result<()> {
    if key.len() != 32 {
        return Err(CoreError::config("data key must be 32 bytes"));
    }
    Ok(())
}
