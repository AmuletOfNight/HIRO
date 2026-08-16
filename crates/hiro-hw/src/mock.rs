//! Deterministic mock video source for tests and development.
//!
//! Frames are synthetic grayscale patterns. Sequences alternate between
//! noise and a bright "face-like" blob in the center so pipelines and
//! liveness checks have something recognizable to chew on.

use std::time::Duration;

use hiro_core::CameraIdentity;

use crate::frame::{Frame, PixelFormat};
use crate::mock_util::shift_xorshift;
use crate::{capture::VideoSource, HwResult};

pub struct MockSource {
    pub width: u32,
    pub height: u32,
    pub face_frames: Vec<u32>,
    /// When set, every `k`th frame is a face frame. Stateless pattern for
    /// long-running tests.
    pub face_every: Option<u32>,
    pub frames_emitted: usize,
    rng_state: u64,
    started: bool,
}

impl MockSource {
    /// Create a mock that emits synthetic frames endlessly.
    ///
    /// Frames whose 1-based sequence number appears in `face_frames` (or
    /// matches `face_every`) contain a bright face-like blob; all frames
    /// carry subtle noise so liveness variance is non-zero.
    pub fn new(width: u32, height: u32, face_frames: Vec<u32>) -> Self {
        Self {
            width,
            height,
            face_frames,
            face_every: None,
            frames_emitted: 0,
            rng_state: 0x9E37_79B9_7F4A_7C15,
            started: false,
        }
    }

    fn synth(&mut self) -> Frame {
        self.frames_emitted += 1;
        let seq = self.frames_emitted as u32;
        let has_face = self.face_frames.contains(&seq)
            || self
                .face_every
                .is_some_and(|k| k > 0 && seq.is_multiple_of(k));
        let (w, h) = (self.width as usize, self.height as usize);
        let mut data = Vec::with_capacity(w * h);
        for y in 0..h {
            for x in 0..w {
                let base = if has_face {
                    let cx = (w / 2) as i64;
                    let cy = (h / 2) as i64;
                    let dx = x as i64 - cx;
                    let dy = y as i64 - cy;
                    let r2 = ((w.min(h) / 3) as i64).pow(2);
                    if dx * dx + dy * dy < r2 {
                        220u8
                    } else {
                        30u8
                    }
                } else {
                    90u8
                };
                let noise = (shift_xorshift(&mut self.rng_state) % 12) as u8;
                data.push(base.wrapping_add(noise).wrapping_sub(6));
            }
        }
        Frame::new(self.width, self.height, PixelFormat::Gray8, data, seq)
    }
}

impl VideoSource for MockSource {
    fn start(&mut self) -> HwResult<()> {
        self.started = true;
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> HwResult<Option<Frame>> {
        if !self.started {
            return Ok(None);
        }
        Ok(Some(self.synth()))
    }

    fn stop(&mut self) {
        self.started = false;
    }

    fn identity(&self) -> CameraIdentity {
        CameraIdentity {
            vendor_id: Some(0xFFFF),
            product_id: Some(0x0001),
            bus_info: Some("mock".into()),
            serial: None,
        }
    }

    fn describe(&self) -> String {
        format!("mock {}x{}", self.width, self.height)
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_emits_face_frames() {
        let mut m = MockSource::new(64, 48, vec![3, 7]);
        m.start().unwrap();
        for i in 1..=10u32 {
            let f = m.next_frame(Duration::from_millis(10)).unwrap().unwrap();
            let gray = f.to_gray().unwrap();
            let (w, h) = (f.width as usize, f.height as usize);
            let center = gray[(h / 2 - 1) * w + w / 2 - 1];
            let border = gray[0];
            if i == 3 || i == 7 {
                assert!(
                    center > 200,
                    "face frame {i}: center should be bright ({center})"
                );
                assert!(
                    border < 60,
                    "face frame {i}: border should be dark ({border})"
                );
            } else {
                assert!(
                    (center as i32 - border as i32).abs() < 30,
                    "noise frame {i} should be uniform"
                );
            }
        }
    }
}
