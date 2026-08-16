//! IR emitter activation.
//!
//! Windows Hello cameras emit 850 nm light through an IR LED array that is
//! switched on via a UVC extension-unit control. This module tries, in
//! order:
//!
//! 1. An in-process `UVCIOC_CTRL_QUERY` set against a
//!    `(unit, selector, value)` tuple from the quirks DB (vendor-specific).
//! 2. The `linux-enable-ir-emitter` tool, when installed.
//!
//! With neither available, the emitter stays off and the camera may return
//! near-black IR frames — `hiro doctor` reports this.

use std::os::fd::AsRawFd;

use hiro_core::CameraIdentity;

use crate::quirks::{Quirk, QuirkDb};
use crate::{HwError, HwResult};

pub trait Emitter: Send {
    /// Attempt to switch the IR emitter on.
    /// Returns whether the emitter is believed active.
    fn enable(&mut self) -> HwResult<bool>;
    /// Attempt to switch the IR emitter off. Best effort.
    fn disable(&mut self);
}

#[repr(C)]
struct UvcXuControlQuery {
    unit: u8,
    selector: u8,
    query: u8,
    size: u16,
    data: *mut u8,
}

nix::ioctl_readwrite!(uvcioc_ctrl_query, b'u', 0x21, UvcXuControlQuery);

const UVC_SET_CUR: u8 = 0x01;

/// Vendor-extension-unit emitter controller.
pub struct UvcXuEmitter {
    device: String,
    quirk: Quirk,
}

impl UvcXuEmitter {
    pub fn new(device: impl Into<String>, quirk: Quirk) -> Self {
        Self {
            device: device.into(),
            quirk,
        }
    }

    fn xu_ctrl(&self, query: u8, value: u8) -> HwResult<()> {
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device)
            .map_err(|e| HwError::Emitter(format!("cannot open {}: {e}", self.device)))?;
        let mut data = [value, 0u8];
        let mut ctrl = UvcXuControlQuery {
            unit: self.quirk.unit,
            selector: self.quirk.selector,
            query,
            size: data.len() as u16,
            data: data.as_mut_ptr(),
        };
        // SAFETY: ctrl and data are valid for the duration of the call; the
        // kernel reads/writes data through the pointer field.
        unsafe {
            uvcioc_ctrl_query(fd.as_raw_fd(), &mut ctrl).map_err(|e| {
                HwError::Emitter(format!("XU control failed on {}: {e}", self.device))
            })?;
        }
        Ok(())
    }
}

impl Emitter for UvcXuEmitter {
    fn enable(&mut self) -> HwResult<bool> {
        self.xu_ctrl(UVC_SET_CUR, self.quirk.value)?;
        log::info!(
            "IR emitter set via XU unit={} selector={} value={}",
            self.quirk.unit,
            self.quirk.selector,
            self.quirk.value
        );
        Ok(true)
    }

    fn disable(&mut self) {
        let _ = self.xu_ctrl(UVC_SET_CUR, 0);
    }
}

/// Emitter control that shells out to `linux-enable-ir-emitter`.
pub struct ExternalEmitter {
    device: String,
}

impl ExternalEmitter {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
        }
    }

    fn tool_available() -> bool {
        which::exists("linux-enable-ir-emitter")
    }

    fn run(&self) -> HwResult<()> {
        // v7 CLI: `linux-enable-ir-emitter [--device D] {configure,run,test,tweak}`.
        // `run` applies the saved configuration; `configure` is the
        // one-time interactive setup the admin must have done.
        let out = std::process::Command::new("linux-enable-ir-emitter")
            .arg("--device")
            .arg(&self.device)
            .arg("run")
            .output()
            .map_err(|e| HwError::Emitter(format!("cannot run linux-enable-ir-emitter: {e}")))?;
        if !out.status.success() {
            return Err(HwError::Emitter(format!(
                "linux-enable-ir-emitter failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
}

impl Emitter for ExternalEmitter {
    fn enable(&mut self) -> HwResult<bool> {
        if !Self::tool_available() {
            return Err(HwError::Emitter(
                "linux-enable-ir-emitter is not installed".into(),
            ));
        }
        self.run()?;
        log::info!(
            "IR emitter enabled via linux-enable-ir-emitter for {}",
            self.device
        );
        Ok(true)
    }

    fn disable(&mut self) {}
}

/// Automatic strategy: quirks DB first, external tool second.
pub struct AutoEmitter {
    device: String,
    identity: CameraIdentity,
    quirks: QuirkDb,
    inner: Option<Box<dyn Emitter>>,
}

impl AutoEmitter {
    pub fn new(device: impl Into<String>, identity: CameraIdentity, quirks: QuirkDb) -> Self {
        Self {
            device: device.into(),
            identity,
            quirks,
            inner: None,
        }
    }
}

impl Emitter for AutoEmitter {
    fn enable(&mut self) -> HwResult<bool> {
        if self.inner.is_none() {
            self.inner = match self.quirks.find(&self.identity) {
                Some(q) => Some(Box::new(UvcXuEmitter::new(self.device.clone(), q))),
                None => Some(Box::new(ExternalEmitter::new(self.device.clone()))),
            };
        }
        match self.inner.as_mut().expect("inner set above").enable() {
            Ok(v) => Ok(v),
            Err(e) => {
                log::debug!("primary emitter path failed: {e}");
                let fallback = ExternalEmitter::new(self.device.clone());
                self.inner = Some(Box::new(fallback));
                self.inner.as_mut().expect("fallback set above").enable()
            }
        }
    }

    fn disable(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.disable();
        }
    }
}

/// Build an emitter for a device according to `mode`.
pub fn build_emitter(
    mode: hiro_core::config::EmitterMode,
    device: impl Into<String>,
    identity: CameraIdentity,
    quirks: QuirkDb,
) -> Option<Box<dyn Emitter>> {
    let device = device.into();
    match mode {
        hiro_core::config::EmitterMode::Off => None,
        hiro_core::config::EmitterMode::Auto => {
            Some(Box::new(AutoEmitter::new(device, identity, quirks)))
        }
        hiro_core::config::EmitterMode::External => Some(Box::new(ExternalEmitter::new(device))),
    }
}

/// Whether `linux-enable-ir-emitter` is installed; used by diagnostics.
pub fn external_tool_present() -> bool {
    which::exists("linux-enable-ir-emitter")
}

/// Minimal `which`-style lookup without an extra dependency.
mod which {
    use std::path::Path;

    pub fn exists(program: &str) -> bool {
        std::env::var_os("PATH")
            .map(|paths| {
                std::env::split_paths(&paths).any(|dir| {
                    let cand = dir.join(program);
                    cand.is_file() && is_executable(&cand)
                })
            })
            .unwrap_or(false)
    }

    fn is_executable(p: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
}
