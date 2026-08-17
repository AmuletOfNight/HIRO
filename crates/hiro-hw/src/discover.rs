//! Discovery of V4L2 camera nodes and IR-node heuristics.

use std::path::{Path, PathBuf};

use hiro_core::{proto::CameraProbe, CameraIdentity};
use v4l::capability::Flags as CapabilityFlags;
use v4l::prelude::*;
use v4l::video::traits::Capture;

use crate::{HwError, HwResult};

/// All `/dev/video*` nodes, sorted by index.
pub fn video_devices() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir("/dev")
        .map(|rd| {
            rd.filter_map(|e| {
                let name = e.ok()?.file_name();
                let name = name.to_string_lossy().into_owned();
                if name.len() > 5
                    && name.starts_with("video")
                    && name[5..].bytes().all(|b| b.is_ascii_digit())
                {
                    Some(PathBuf::from("/dev").join(name))
                } else {
                    None
                }
            })
            .collect()
        })
        .unwrap_or_default();
    paths.sort_by_key(|p| {
        p.file_name()
            .and_then(|n| {
                n.to_string_lossy()
                    .strip_prefix("video")?
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(u32::MAX)
    });
    paths
}

/// Probe a single device node.
pub fn probe_device(path: &Path) -> HwResult<CameraProbe> {
    let path_str = path.to_string_lossy();
    let dev = Device::with_path(path)
        .map_err(|e| HwError::Camera(format!("cannot open {path_str}: {e}")))?;

    let caps = dev
        .query_caps()
        .map_err(|e| HwError::Camera(format!("cannot query caps of {path_str}: {e}")))?;
    let captures_video = caps.capabilities.contains(CapabilityFlags::VIDEO_CAPTURE);

    let formats: Vec<String> = dev
        .enum_formats()
        .map(|fs| fs.into_iter().map(|f| f.fourcc.to_string()).collect())
        .unwrap_or_default();

    let (is_ir_candidate, why_ir) =
        ir_candidate(&caps.card, &caps.driver, &formats, captures_video);

    let identity = usb_identity(&caps.bus, path);

    Ok(CameraProbe {
        path: path_str.into_owned(),
        driver: Some(caps.driver),
        card: Some(caps.card),
        bus_info: Some(caps.bus),
        identity,
        is_ir_candidate,
        why_ir,
        captures_video,
        formats,
    })
}

/// Probe every `/dev/video*` node. Devices that fail to open are skipped
/// (with a debug log) rather than failing the whole probe.
pub fn probe_devices() -> Vec<CameraProbe> {
    video_devices()
        .into_iter()
        .filter_map(|p| match probe_device(&p) {
            Ok(probe) => Some(probe),
            Err(e) => {
                log::debug!("skipping {}: {e}", p.display());
                None
            }
        })
        .collect()
}

/// Pick the best IR-capable node, or fall back to the first UVC capture
/// node when none is detected (the daemon then refuses auth if
/// `require_ir` is set).
pub fn pick_capture_device(
    probes: &[CameraProbe],
    preferred: Option<&str>,
) -> HwResult<CameraProbe> {
    if let Some(pref) = preferred {
        if let Some(p) = probes.iter().find(|p| p.path == pref) {
            return Ok(p.clone());
        }
        return Err(HwError::Invalid(format!(
            "configured device {pref} not found"
        )));
    }
    if let Some(p) = probes
        .iter()
        .find(|p| p.captures_video && p.is_ir_candidate && p.driver.as_deref() == Some("uvcvideo"))
    {
        return Ok(p.clone());
    }
    if let Some(p) = probes
        .iter()
        .find(|p| p.captures_video && p.is_ir_candidate)
    {
        return Ok(p.clone());
    }
    if let Some(p) = probes
        .iter()
        .find(|p| p.captures_video && p.driver.as_deref() == Some("uvcvideo"))
    {
        return Ok(p.clone());
    }
    probes
        .iter()
        .find(|p| p.captures_video)
        .cloned()
        .ok_or(HwError::NoCamera)
}

/// Heuristic IR classification of a camera node.
fn ir_candidate(
    card: &str,
    driver: &str,
    formats: &[String],
    captures_video: bool,
) -> (bool, String) {
    if !captures_video {
        return (false, "not a capture node".into());
    }
    if driver != "uvcvideo" {
        return (false, format!("driver is {driver}, not uvcvideo"));
    }
    let name = card.to_ascii_lowercase();
    let name_ir = name.contains("ir ")
        || name.contains("ir-")
        || name.contains("infrared")
        || name.ends_with(" ir")
        || name.contains("ir camera")
        || name.contains("camera ir");
    if name_ir {
        return (true, format!("card name suggests IR: {card}"));
    }
    let has_color = formats
        .iter()
        .any(|f| matches!(f.as_str(), "YUYV" | "MJPG" | "RGB3" | "NV12"));
    let has_grayish = formats
        .iter()
        .any(|f| matches!(f.as_str(), "GRAY" | "GREY" | "Y8  " | "Y16 "));
    if has_grayish && !has_color {
        return (
            true,
            format!("grayscale-only formats ({formats:?}) suggest an IR sensor"),
        );
    }
    if name.contains("integrated") && has_color {
        return (false, format!("integrated RGB camera ({formats:?})"));
    }
    (
        false,
        format!("no IR signal in name or formats ({formats:?})"),
    )
}

/// Derive USB vendor/product/serial identity via sysfs.
///
/// `/sys/class/video4linux/videoN/device` points at the USB interface
/// device; walking up a few levels reaches the USB device node carrying
/// `idVendor`, `idProduct`, and `serial`.
pub fn usb_identity(bus_info: &str, video_path: &Path) -> CameraIdentity {
    let name = video_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    let mut identity = CameraIdentity {
        bus_info: Some(bus_info.to_string()),
        ..CameraIdentity::default()
    };
    let Some(name) = name else { return identity };
    let class = PathBuf::from("/sys/class/video4linux")
        .join(name)
        .join("device");

    let Ok(mut current) = std::fs::canonicalize(&class) else {
        return identity;
    };
    for _ in 0..6 {
        let id_vendor = current.join("idVendor");
        let id_product = current.join("idProduct");
        if id_vendor.exists() && id_product.exists() {
            let read_hex = |p: &Path| {
                std::fs::read_to_string(p)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .and_then(|s| u16::from_str_radix(s.as_str(), 16).ok())
            };
            identity.vendor_id = read_hex(&id_vendor);
            identity.product_id = read_hex(&id_product);
            if let Ok(serial) = std::fs::read_to_string(current.join("serial")) {
                let serial = serial.trim().to_string();
                if !serial.is_empty() {
                    identity.serial = Some(serial);
                }
            }
            break;
        }
        let Some(parent) = current.parent().map(Path::to_path_buf) else {
            break;
        };
        current = parent;
    }
    identity
}

/// The canonical sysfs device path for a V4L2 node, e.g.
/// `/sys/devices/pci0000:00/.../1-5:1.0/video4linux/video0`. Resolved from
/// `/sys/class/video4linux/videoN/device`. USB descriptors cannot influence
/// this path, so it is a strong component of the camera-pinning binding.
pub fn sysfs_device_path(video_path: &Path) -> Option<String> {
    let name = video_path.file_name()?;
    let class = PathBuf::from("/sys/class/video4linux").join(name).join("device");
    std::fs::canonicalize(&class)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Human-readable summary of all probes; used by `hiro doctor`.
pub fn summarize(probes: &[CameraProbe]) -> String {
    let mut out = String::new();
    for p in probes {
        let mut line = format!(
            "{}  card={}  driver={}",
            p.path,
            p.card.clone().unwrap_or_default(),
            p.driver.clone().unwrap_or_default()
        );
        if p.captures_video {
            line.push_str("  capture=yes");
        }
        if p.is_ir_candidate {
            line.push_str(&format!("  IR-CANDIDATE ({})", p.why_ir));
        }
        line.push_str(&format!("  formats=[{}]", p.formats.join(", ")));
        out.push_str(&line);
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("no /dev/video* devices found\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_heuristics_name() {
        let (ir, why) = ir_candidate("Integrated IR Camera", "uvcvideo", &["YUYV".into()], true);
        assert!(ir, "{why}");
    }

    #[test]
    fn ir_heuristics_grayscale_only() {
        let (ir, why) = ir_candidate("USB Camera", "uvcvideo", &["GRAY".into()], true);
        assert!(ir, "{why}");
    }

    #[test]
    fn rgb_not_ir() {
        let (ir, _) = ir_candidate(
            "Integrated Camera",
            "uvcvideo",
            &["YUYV".into(), "MJPG".into()],
            true,
        );
        assert!(!ir);
    }

    #[test]
    fn non_uvc_rejected() {
        let (ir, _) = ir_candidate("Integrated IR Camera", "ipu6", &["YUYV".into()], true);
        assert!(!ir);
    }

    #[test]
    fn non_capture_rejected() {
        let (ir, _) = ir_candidate("Integrated IR Camera", "uvcvideo", &[], false);
        assert!(!ir);
    }

    #[test]
    fn picker_prefers_ir_uvc() {
        let mk = |path: &str, card: &str, driver: &str, ir: bool| CameraProbe {
            path: path.into(),
            driver: Some(driver.into()),
            card: Some(card.into()),
            bus_info: Some("usb-x".into()),
            identity: CameraIdentity::default(),
            is_ir_candidate: ir,
            why_ir: String::new(),
            captures_video: true,
            formats: vec![],
        };
        let probes = vec![
            mk("/dev/video0", "Integrated Camera", "uvcvideo", false),
            mk("/dev/video2", "Integrated IR Camera", "uvcvideo", true),
            mk("/dev/video4", "Metadata", "uvcvideo", false),
        ];
        let picked = pick_capture_device(&probes, None).unwrap();
        assert_eq!(picked.path, "/dev/video2");

        let picked = pick_capture_device(&probes, Some("/dev/video0")).unwrap();
        assert_eq!(picked.path, "/dev/video0");

        assert!(pick_capture_device(&probes, Some("/dev/video9")).is_err());
    }

    #[test]
    fn picker_falls_back_to_uvc_rgb() {
        let probes = vec![CameraProbe {
            path: "/dev/video0".into(),
            driver: Some("uvcvideo".into()),
            card: Some("Integrated Camera".into()),
            bus_info: Some("usb-x".into()),
            identity: CameraIdentity::default(),
            is_ir_candidate: false,
            why_ir: String::new(),
            captures_video: true,
            formats: vec![],
        }];
        let picked = pick_capture_device(&probes, None).unwrap();
        assert_eq!(picked.path, "/dev/video0");
    }
}
