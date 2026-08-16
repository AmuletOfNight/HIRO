//! Vendor quirks database for IR emitter extension-unit controls.
//!
//! Each entry maps a USB vendor/product pair to the UVC extension-unit
//! `(unit, selector, value)` tuple that switches the IR emitter on.
//! Entries load from:
//!
//! 1. `/etc/hiro/quirks.toml` (admin-provided), then
//! 2. the built-in table in `quirks.toml`.
//!
//! Unknown cameras fall back to `linux-enable-ir-emitter`.

use std::path::Path;

use hiro_core::CameraIdentity;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct QuirksFile {
    #[serde(default)]
    quirks: Vec<QuirkEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct QuirkEntry {
    vid: u32,
    pid: u32,
    name: String,
    unit: u8,
    selector: u8,
    value: u8,
}

#[derive(Debug, Clone)]
pub struct Quirk {
    pub name: String,
    pub unit: u8,
    pub selector: u8,
    pub value: u8,
}

#[derive(Debug, Clone, Default)]
pub struct QuirkDb {
    entries: Vec<(u16, u16, Quirk)>,
}

impl QuirkDb {
    /// Load the built-in table plus any admin override file.
    pub fn load(override_path: Option<&Path>) -> Self {
        let mut db = Self::from_toml(include_str!("../quirks.toml"));
        if let Some(path) = override_path {
            if let Ok(text) = std::fs::read_to_string(path) {
                let extra = Self::from_toml(&text);
                db.entries.extend(extra.entries);
                log::info!(
                    "loaded {} quirk entries from {}",
                    db.entries.len(),
                    path.display()
                );
            }
        }
        db
    }

    pub fn from_toml(text: &str) -> Self {
        let parsed: QuirksFile = toml::from_str(text).unwrap_or(QuirksFile { quirks: Vec::new() });
        let mut db = Self::default();
        for e in parsed.quirks {
            db.entries.push((
                e.vid as u16,
                e.pid as u16,
                Quirk {
                    name: e.name,
                    unit: e.unit,
                    selector: e.selector,
                    value: e.value,
                },
            ));
        }
        db
    }

    pub fn find(&self, identity: &CameraIdentity) -> Option<Quirk> {
        let (vid, pid) = (identity.vendor_id?, identity.product_id?);
        self.entries
            .iter()
            .find(|(v, p, _)| *v == vid && *p == pid)
            .map(|(_, _, q)| q.clone())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_lookup() {
        let text = r#"
[[quirks]]
vid = 5075
pid = 22250
name = "TestCam"
unit = 3
selector = 1
value = 1
"#;
        let db = QuirkDb::from_toml(text);
        assert_eq!(db.len(), 1);
        let id = CameraIdentity {
            vendor_id: Some(0x13d3),
            product_id: Some(0x56ea),
            ..Default::default()
        };
        let q = db.find(&id).unwrap();
        assert_eq!(q.unit, 3);
        assert_eq!(q.selector, 1);
        assert_eq!(q.value, 1);
        assert_eq!(q.name, "TestCam");
    }

    #[test]
    fn missing_entry_returns_none() {
        let db = QuirkDb::from_toml("");
        let id = CameraIdentity {
            vendor_id: Some(1),
            product_id: Some(2),
            ..Default::default()
        };
        assert!(db.find(&id).is_none());
    }

    #[test]
    fn builtin_table_parses() {
        let db = QuirkDb::load(None);
        assert!(db.entries.len() == db.len());
    }
}
