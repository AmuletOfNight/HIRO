//! Anti-spoof liveness signals computed over a capture window.
//!
//! Two cheap, model-free checks:
//!
//! * Temporal frame variance: consecutive IR frames of a living subject
//!   always differ slightly; a static photo or screen replay does not.
//! * Landmark micro-motion: a live face's detected landmarks jitter and
//!   drift between frames; landmarks of a static spoof are frozen.

pub struct VarianceTracker {
    last: Option<Vec<u8>>,
    pub max_diff: f32,
}

impl VarianceTracker {
    pub fn new() -> Self {
        Self {
            last: None,
            max_diff: 0.0,
        }
    }

    /// Feed the next grayscale frame; returns the mean absolute difference
    /// against the previous frame (0.0 for the first frame).
    pub fn update(&mut self, gray: &[u8]) -> f32 {
        let diff = match &self.last {
            Some(prev) => frame_diff(prev, gray),
            None => 0.0,
        };
        self.last = Some(gray.to_vec());
        if diff > self.max_diff {
            self.max_diff = diff;
        }
        diff
    }
}

impl Default for VarianceTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MotionTracker {
    last: Option<[[f32; 2]; 5]>,
    pub max_motion: f32,
}

impl MotionTracker {
    pub fn new() -> Self {
        Self {
            last: None,
            max_motion: 0.0,
        }
    }

    /// Feed the next detection's landmarks (normalized [0,1]); returns the
    /// mean landmark displacement against the previous detection.
    pub fn update(&mut self, landmarks: &[[f32; 2]; 5]) -> f32 {
        let motion = match &self.last {
            Some(prev) => {
                let mut sum = 0.0f32;
                for (a, b) in prev.iter().zip(landmarks) {
                    let dx = a[0] - b[0];
                    let dy = a[1] - b[1];
                    sum += (dx * dx + dy * dy).sqrt();
                }
                sum / 5.0
            }
            None => 0.0,
        };
        self.last = Some(*landmarks);
        if motion > self.max_motion {
            self.max_motion = motion;
        }
        motion
    }
}

impl Default for MotionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Mean absolute difference of two same-length luma buffers.
pub fn frame_diff(a: &[u8], b: &[u8]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut acc = 0u64;
    for (x, y) in a.iter().zip(b) {
        acc += u64::from(x.abs_diff(*y));
    }
    acc as f32 / a.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variance_detects_change() {
        let mut t = VarianceTracker::new();
        assert_eq!(t.update(&[0; 16]), 0.0);
        let d = t.update(&[255; 16]);
        assert!(d > 200.0);
        assert_eq!(t.update(&[255; 16]), 0.0);
    }

    #[test]
    fn motion_detects_drift() {
        let mut t = MotionTracker::new();
        let a = [[0.5; 2]; 5];
        assert_eq!(t.update(&a), 0.0);
        let mut b = a;
        b[0][0] += 0.01;
        let m = t.update(&b);
        assert!(m > 0.001, "{m}");
    }
}
