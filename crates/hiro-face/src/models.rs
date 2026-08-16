//! Model manifest: names, files, pinned SHA-256 hashes, licenses.
//!
//! The daemon verifies every model file against this manifest at load
//! time; `hiro doctor` and `scripts/fetch-models.sh` use it too.

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::FaceError;
use crate::FaceResult;

#[derive(Debug, Clone, Deserialize)]
pub struct ModelEntry {
    pub file: String,
    pub url: String,
    pub sha256: String,
    pub license: String,
    /// Expected square input size, when the model has one.
    #[serde(default)]
    pub input_w: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub detector: std::collections::BTreeMap<String, ModelEntry>,
    pub embedder: std::collections::BTreeMap<String, ModelEntry>,
}

impl Manifest {
    pub fn parse(toml_text: &str) -> FaceResult<Self> {
        toml::from_str(toml_text).map_err(|e| FaceError::Config(format!("bad model manifest: {e}")))
    }

    pub fn builtin() -> FaceResult<Self> {
        Self::parse(include_str!("../models/manifest.toml"))
    }

    pub fn entry(&self, kind: &str, name: &str) -> FaceResult<&ModelEntry> {
        let map = match kind {
            "detector" => &self.detector,
            "embedder" => &self.embedder,
            other => return Err(FaceError::Config(format!("unknown model kind: {other}"))),
        };
        map.get(name)
            .ok_or_else(|| FaceError::Config(format!("unknown model: {kind}/{name}")))
    }

    /// Verify that every manifest entry exists and hashes correctly.
    /// Entries with an empty `sha256` (not yet pinned) only need to exist.
    pub fn verify_all(&self, model_dir: &Path) -> FaceResult<()> {
        let mut problems = Vec::new();
        for (kind, map) in [("detector", &self.detector), ("embedder", &self.embedder)] {
            for (name, entry) in map {
                let path = model_dir.join(&entry.file);
                if entry.sha256.is_empty() {
                    if path.is_file() {
                        log::warn!("model {kind}/{name}: hash not pinned; pin it in the manifest");
                        continue;
                    }
                    problems.push(format!("{kind}/{name}: missing {}", path.display()));
                    continue;
                }
                match verify_file(&path, &entry.sha256) {
                    Ok(()) => log::info!("model {kind}/{name}: OK ({})", path.display()),
                    Err(e) => problems.push(format!("{kind}/{name}: {e}")),
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(FaceError::Integrity(problems.join("; ")))
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn verify_file(path: &Path, expected: &str) -> FaceResult<()> {
    let data = std::fs::read(path)
        .map_err(|e| FaceError::Integrity(format!("cannot read {}: {e}", path.display())))?;
    let actual = sha256_hex(&data);
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(FaceError::Integrity(format!(
            "{}: hash mismatch (expected {expected}, got {actual})",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_manifest_parses() {
        let m = Manifest::builtin().unwrap();
        assert!(m.detector.contains_key("scrfd"));
        assert!(m.embedder.contains_key("auraface"));
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_file_works() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("m.bin");
        std::fs::write(&f, b"abc").unwrap();
        assert!(verify_file(
            &f,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        .is_ok());
        assert!(verify_file(&f, "deadbeef").is_err());
    }

    #[test]
    fn verify_all_requires_files() {
        let m = Manifest::builtin().unwrap();
        let empty = tempfile::tempdir().unwrap();
        assert!(m.verify_all(empty.path()).is_err());
    }
}
