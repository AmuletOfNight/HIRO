//! TPM 2.0-sealed AES key manager.
//!
//! The 256-bit template data key never rests on disk in plaintext: it is
//! sealed under a TPM 2.0 primary key (ECC P-256, storage hierarchy,
//! deterministic template, so the same primary is recreated on every boot)
//! and stored as a TPM2B_PUBLIC + TPM2B_PRIVATE blob in the keyfile.
//!
//! After load/create, only the in-memory key remains; the TPM context is
//! dropped and all template encryption is plain AES-256-GCM.
//!
//! Blob format (no PCR binding, matching the proven facelock layout):
//! `0x01 | pub_len(u32 LE) | marshalled public | marshalled private`

use std::path::Path;

use hiro_core::{CoreError, Result};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;
use zeroize::Zeroizing;

use crate::{aead_seal, aead_unseal, fill_random, write_keyfile, KeyManager};

pub const SEALED_VERSION_BYTE: u8 = 0x01;

pub struct TpmKeyManager {
    /// The unsealed data key. Wrapped in `Zeroizing` so the in-memory key
    /// is wiped when the manager is dropped.
    key: Zeroizing<[u8; 32]>,
}

impl TpmKeyManager {
    /// Load the AES key from a TPM-sealed keyfile.
    pub fn load(path: &Path) -> Result<Self> {
        let blob = std::fs::read(path).map_err(|e| {
            CoreError::io(format!(
                "cannot read sealed keyfile {}: {e}",
                path.display()
            ))
        })?;
        let key = unseal_key_from_blob(&blob)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// Generate a fresh AES key, seal it under the TPM, and write the blob
    /// to `path` (mode 0600). Fails if the file already exists.
    pub fn create(path: &Path) -> Result<Self> {
        let mut key = [0u8; 32];
        fill_random(&mut key);
        let blob = seal_key_to_blob(&key)?;
        write_keyfile(path, &blob)?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }
}

impl KeyManager for TpmKeyManager {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        aead_seal(&self.key[..], aad, plaintext)
    }

    fn unseal(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        aead_unseal(&self.key[..], aad, ciphertext)
    }

    fn tpm_available(&self) -> bool {
        true
    }

    fn kind(&self) -> &'static str {
        "tpm2"
    }
}

fn open_context() -> Result<Context> {
    // TCTI selection: $TPM2TOOLS_TCTI / $TCTI / $TEST_TCTI, else the
    // default device node.
    let tcti = match TctiNameConf::from_environment_variable() {
        Ok(conf) => conf,
        Err(_) => TctiNameConf::Device(Default::default()),
    };
    Context::new(tcti).map_err(|e| CoreError::io(format!("cannot open TPM 2.0 device: {e}")))
}

/// Create the deterministic ECC P-256 restricted-decryption primary under
/// the storage hierarchy. The same template reproduces the same key, so no
/// TPM persistence is needed across daemon restarts.
fn create_primary(context: &mut Context) -> Result<KeyHandle> {
    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_no_da(true)
        .build()
        .map_err(|e| CoreError::internal(format!("cannot build primary attributes: {e}")))?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .build()
        .map_err(|e| CoreError::internal(format!("cannot build ECC parameters: {e}")))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| CoreError::internal(format!("cannot build primary public: {e}")))?;

    let primary = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .map_err(|e| CoreError::internal(format!("TPM create_primary failed: {e}")))?;
    Ok(primary.key_handle)
}

/// Seal a 32-byte key into a version-prefixed TPM blob.
pub fn seal_key_to_blob(key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut context = open_context()?;
    let primary = create_primary(&mut context)?;

    let sensitive = SensitiveData::try_from(key.to_vec())
        .map_err(|e| CoreError::internal(format!("key too large for TPM seal: {e}")))?;

    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .build()
        .map_err(|e| CoreError::internal(format!("cannot build object attributes: {e}")))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .map_err(|e| CoreError::internal(format!("cannot build sealed object public: {e}")))?;

    let (private, public_out) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary, public, None, Some(sensitive), None, None)
        })
        .map_err(|e| CoreError::internal(format!("TPM seal failed: {e}")))
        .map(|result| (result.out_private, result.out_public))?;

    let pub_bytes = public_out
        .marshall()
        .map_err(|e| CoreError::internal(format!("cannot marshal public: {e}")))?;
    let priv_bytes = marshal_private(&private);

    let mut blob = Vec::with_capacity(5 + pub_bytes.len() + priv_bytes.len());
    blob.push(SEALED_VERSION_BYTE);
    blob.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&pub_bytes);
    blob.extend_from_slice(&priv_bytes);
    Ok(blob)
}

/// Unseal a 32-byte key from a TPM blob.
pub fn unseal_key_from_blob(blob: &[u8]) -> Result<[u8; 32]> {
    if blob.len() < 5 || blob[0] != SEALED_VERSION_BYTE {
        return Err(CoreError::invalid("not a TPM-sealed HIRO key blob"));
    }
    let pub_len = u32::from_le_bytes([blob[1], blob[2], blob[3], blob[4]]) as usize;
    let body = &blob[5..];
    if body.len() < pub_len {
        return Err(CoreError::invalid("sealed blob truncated (public)"));
    }
    let (pub_bytes, priv_bytes) = (&body[..pub_len], &body[pub_len..]);

    let public = tss_esapi::structures::Public::unmarshall(pub_bytes)
        .map_err(|e| CoreError::invalid(format!("cannot unmarshal public: {e}")))?;
    let private = unmarshal_private(priv_bytes)?;

    let mut context = open_context()?;
    let primary = create_primary(&mut context)?;

    let loaded = context
        .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
        .map_err(|e| CoreError::internal(format!("TPM load failed: {e}")))?;
    let object: tss_esapi::handles::ObjectHandle = loaded.into();

    let unsealed = context
        .execute_with_nullauth_session(|ctx| ctx.unseal(object))
        .map_err(|e| CoreError::internal(format!("TPM unseal failed: {e}")));
    let _ = context.flush_context(object);

    let data = unsealed?;
    if data.len() != 32 {
        return Err(CoreError::invalid(format!(
            "unsealed key is {} bytes, expected 32",
            data.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(data.as_slice());
    Ok(key)
}

/// TPM2B_PRIVATE wire format: `size(u16 LE) || bytes`. The 7.x buffer
/// types do not implement `Marshall`, so this is done by hand — the layout
/// is fixed by the TPM 2.0 spec.
fn marshal_private(private: &Private) -> Vec<u8> {
    let body: &[u8] = private.as_ref();
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn unmarshal_private(bytes: &[u8]) -> Result<Private> {
    if bytes.len() < 2 {
        return Err(CoreError::invalid("private blob too short"));
    }
    let size = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + size {
        return Err(CoreError::invalid("private blob truncated"));
    }
    Private::try_from(bytes[2..2 + size].to_vec())
        .map_err(|e| CoreError::invalid(format!("invalid private blob: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_marshal_roundtrip() {
        let private = Private::try_from(vec![1u8, 2, 3, 4, 5, 6]).unwrap();
        let bytes = marshal_private(&private);
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[0..2], &[6, 0]);
        let back = unmarshal_private(&bytes).unwrap();
        assert_eq!(&**back, &**private);
    }

    #[test]
    fn private_unmarshal_rejects_truncation() {
        assert!(unmarshal_private(&[1]).is_err());
        assert!(unmarshal_private(&[10, 0, 1, 2, 3]).is_err());
    }

    #[test]
    fn key_blob_rejects_wrong_version() {
        assert!(unseal_key_from_blob(&[0x02, 0, 0, 0, 0]).is_err());
        assert!(unseal_key_from_blob(b"short").is_err());
    }
}
