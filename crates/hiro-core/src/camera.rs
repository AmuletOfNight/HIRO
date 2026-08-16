use serde::{Deserialize, Serialize};

/// Identity of the physical camera, used for camera pinning.
///
/// Recorded at enrollment; verification refuses to run if the camera
/// identity at authentication time differs from the enrolled one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CameraIdentity {
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    pub bus_info: Option<String>,
    pub serial: Option<String>,
}

impl CameraIdentity {
    pub fn fingerprint(&self) -> String {
        let vid = self
            .vendor_id
            .map_or_else(|| "?".into(), |v| format!("{v:04x}"));
        let pid = self
            .product_id
            .map_or_else(|| "?".into(), |p| format!("{p:04x}"));
        let bus = self.bus_info.clone().unwrap_or_else(|| "?".into());
        let serial = self.serial.clone().unwrap_or_else(|| "?".into());
        format!("{vid}:{pid}:{bus}:{serial}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable() {
        let id = CameraIdentity {
            vendor_id: Some(0x13d3),
            product_id: Some(0x56ea),
            bus_info: Some("usb-0000:00:14.0-5".into()),
            serial: None,
        };
        assert_eq!(id.fingerprint(), "13d3:56ea:usb-0000:00:14.0-5:?");
    }
}
