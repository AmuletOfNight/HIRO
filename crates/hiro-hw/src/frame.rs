//! Frame representation and lightweight image statistics.
//!
//! These helpers are intentionally dependency-free: they operate on raw
//! bytes so the daemon can compute liveness and quality signals without
//! pulling in an image processing stack.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Yuyv,
    Gray8,
    Mjpeg,
    Rgb24,
    Other([u8; 4]),
}

impl PixelFormat {
    pub fn fourcc(&self) -> [u8; 4] {
        match self {
            Self::Yuyv => *b"YUYV",
            Self::Gray8 => *b"GRAY",
            Self::Mjpeg => *b"MJPG",
            Self::Rgb24 => *b"RGB3",
            Self::Other(f) => *f,
        }
    }

    pub fn from_fourcc(bytes: &[u8]) -> Self {
        match bytes {
            b"YUYV" => Self::Yuyv,
            b"GRAY" | b"GREY" => Self::Gray8,
            b"MJPG" => Self::Mjpeg,
            b"RGB3" => Self::Rgb24,
            other if other.len() == 4 => Self::Other([other[0], other[1], other[2], other[3]]),
            _ => Self::Other(*b"????"),
        }
    }

    /// Bytes per pixel for uncompressed formats, when known.
    pub fn bytes_per_pixel(&self) -> Option<usize> {
        match self {
            Self::Yuyv => Some(2),
            Self::Gray8 => Some(1),
            Self::Rgb24 => Some(3),
            Self::Mjpeg | Self::Other(_) => None,
        }
    }
}

/// A captured video frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub data: Vec<u8>,
    /// V4L2 sequence number, or a monotonic counter for mocks.
    pub seq: u32,
    /// Milliseconds since an arbitrary epoch; used for timing checks.
    pub timestamp_ms: u64,
}

impl Frame {
    pub fn new(width: u32, height: u32, format: PixelFormat, data: Vec<u8>, seq: u32) -> Self {
        Self {
            width,
            height,
            format,
            data,
            seq,
            timestamp_ms: 0,
        }
    }

    /// Extract a grayscale (luma) version of the frame.
    ///
    /// YUYV frames drop chroma samples; GRAY8 copies; other formats yield
    /// `None` (callers must convert or reject the camera).
    pub fn to_gray(&self) -> Option<Vec<u8>> {
        match self.format {
            PixelFormat::Gray8 => Some(self.data.clone()),
            PixelFormat::Yuyv => {
                let out_len = (self.width as usize) * (self.height as usize);
                let mut out = Vec::with_capacity(out_len);
                for chunk in self.data.chunks_exact(4) {
                    out.push(chunk[0]);
                }
                if out.len() != out_len {
                    return None;
                }
                Some(out)
            }
            _ => None,
        }
    }
}

/// Mean absolute difference between two same-size luma buffers.
/// Returns `None` when the sizes differ.
pub fn mean_abs_diff(a: &[u8], b: &[u8]) -> Option<f32> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let mut acc = 0u64;
    for (x, y) in a.iter().zip(b) {
        acc += u64::from(x.abs_diff(*y));
    }
    Some(acc as f32 / a.len() as f32)
}

/// Variance of a luma buffer (spread of pixel intensities).
pub fn pixel_variance(luma: &[u8]) -> Option<f32> {
    if luma.is_empty() {
        return None;
    }
    let mean = luma.iter().map(|&v| f64::from(v)).sum::<f64>() / luma.len() as f64;
    let var = luma
        .iter()
        .map(|&v| (f64::from(v) - mean).powi(2))
        .sum::<f64>()
        / luma.len() as f64;
    Some(var as f32)
}

/// Laplacian-variance sharpness estimate on a luma buffer.
/// Higher is sharper; blurry frames score low.
pub fn sharpness(luma: &[u8], width: u32, height: u32) -> Option<f32> {
    let (w, h) = (width as usize, height as usize);
    if w < 3 || h < 3 || luma.len() != w * h {
        return None;
    }
    let at = |x: usize, y: usize| f64::from(luma[y * w + x]);
    let mut lap = Vec::with_capacity((h - 2) * (w - 2));
    for y in 1..h - 1 {
        for x in 1..w - 1 {
            let v = 4.0 * at(x, y) - at(x - 1, y) - at(x + 1, y) - at(x, y - 1) - at(x, y + 1);
            lap.push(v);
        }
    }
    let mean = lap.iter().sum::<f64>() / lap.len() as f64;
    let var = lap.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / lap.len() as f64;
    Some(var as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkers(w: u32, h: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity((w * h) as usize);
        for y in 0..h {
            for x in 0..w {
                v.push(if (x + y) % 2 == 0 { 0 } else { 255 });
            }
        }
        v
    }

    #[test]
    fn gray_extraction_from_yuyv() {
        let yuyv: Vec<u8> = (0..16)
            .map(|i| [i, 0x80, 0x80, 0x80][i as usize % 4])
            .collect();
        let frame = Frame::new(4, 1, PixelFormat::Yuyv, yuyv, 0);
        let gray = frame.to_gray().unwrap();
        assert_eq!(gray, vec![0, 4, 8, 12]);
    }

    #[test]
    fn gray8_passthrough() {
        let frame = Frame::new(2, 1, PixelFormat::Gray8, vec![1, 2], 0);
        assert_eq!(frame.to_gray().unwrap(), vec![1, 2]);
    }

    #[test]
    fn mean_abs_diff_basics() {
        assert_eq!(mean_abs_diff(&[0, 0], &[10, 20]).unwrap(), 15.0);
        assert!(mean_abs_diff(&[0], &[0, 1]).is_none());
        assert!(mean_abs_diff(&[], &[]).is_none());
    }

    #[test]
    fn variance_of_flat_image_is_zero() {
        assert_eq!(pixel_variance(&[50; 100]).unwrap(), 0.0);
    }

    #[test]
    fn sharpness_flat_vs_checker() {
        let flat = vec![128u8; 32 * 32];
        let checker = checkers(32, 32);
        let sf = sharpness(&flat, 32, 32).unwrap();
        let sc = sharpness(&checker, 32, 32).unwrap();
        assert!(sf < 1.0, "flat image should be unsharp, got {sf}");
        assert!(
            sc > sf * 100.0,
            "checker should be far sharper: {sc} vs {sf}"
        );
    }
}
