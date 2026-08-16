//! Software (no-TPM) key manager: a random 256-bit data key in a
//! root-only keyfile, used directly for AES-256-GCM.

use std::path::Path;

use hiro_core::{CoreError, Result};

use crate::{aead_seal, aead_unseal, fill_random, read_keyfile, write_keyfile, KeyManager};

pub struct SoftwareKeyManager {
    key: [u8; 32],
}

impl SoftwareKeyManager {
    /// Load the data key from `path` (creating nothing).
    pub fn load(path: &Path) -> Result<Self> {
        let data = read_keyfile(path)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(Self { key })
    }

    /// Generate a fresh data key and write it to `path` with mode 0600.
    /// Fails if the file already exists.
    pub fn create(path: &Path) -> Result<Self> {
        let mut key = [0u8; 32];
        fill_random(&mut key);
        write_keyfile(path, &key)?;
        Ok(Self { key })
    }

    /// Build directly from a known key (tests, import flows).
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl KeyManager for SoftwareKeyManager {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        aead_seal(&self.key, plaintext)
    }

    fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        aead_unseal(&self.key, ciphertext)
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
