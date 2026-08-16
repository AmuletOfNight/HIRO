//! Grayscale image preprocessing: resize, normalize, channel expansion.

use crate::FaceError;
use crate::FaceResult;

/// Bilinear resize of a grayscale buffer.
pub fn resize_gray(src: &[u8], sw: u32, sh: u32, dw: u32, dh: u32) -> FaceResult<Vec<u8>> {
    if src.len() != (sw * sh) as usize {
        return Err(FaceError::Pipeline(format!(
            "source buffer size {} does not match {sw}x{sh}",
            src.len()
        )));
    }
    if dw == 0 || dh == 0 {
        return Err(FaceError::Pipeline("zero-size destination".into()));
    }
    let (sw, sh, dw, dh) = (sw as usize, sh as usize, dw as usize, dh as usize);
    let mut out = vec![0u8; dw * dh];
    let fx = if dw > 1 {
        (sw - 1) as f64 / (dw - 1) as f64
    } else {
        0.0
    };
    let fy = if dh > 1 {
        (sh - 1) as f64 / (dh - 1) as f64
    } else {
        0.0
    };
    for y in 0..dh {
        let sy = y as f64 * fy;
        let y0 = sy.floor() as usize;
        let y1 = (y0 + 1).min(sh - 1);
        let wy = sy - y0 as f64;
        for x in 0..dw {
            let sx = x as f64 * fx;
            let x0 = sx.floor() as usize;
            let x1 = (x0 + 1).min(sw - 1);
            let wx = sx - x0 as f64;
            let v00 = f64::from(src[y0 * sw + x0]);
            let v01 = f64::from(src[y0 * sw + x1]);
            let v10 = f64::from(src[y1 * sw + x0]);
            let v11 = f64::from(src[y1 * sw + x1]);
            let top = v00 * (1.0 - wx) + v01 * wx;
            let bottom = v10 * (1.0 - wx) + v11 * wx;
            let v = top * (1.0 - wy) + bottom * wy;
            out[y * dw + x] = v.round().clamp(0.0, 255.0) as u8;
        }
    }
    Ok(out)
}

/// ArcFace-style normalization: `(x / 255 - 0.5) / 0.5` into `[-1, 1]`.
pub fn normalize_gray(gray: &[u8]) -> Vec<f32> {
    gray.iter()
        .map(|&v| (f32::from(v) / 255.0 - 0.5) / 0.5)
        .collect()
}

/// Expand normalized grayscale to three NCHW (channel-major) channels, as
/// expected by RGB-trained ONNX models with `[N, C, H, W]` inputs.
pub fn gray_to_rgb3(gray_norm: &[f32]) -> Vec<f32> {
    let mut out = Vec::with_capacity(gray_norm.len() * 3);
    out.extend_from_slice(gray_norm);
    out.extend_from_slice(gray_norm);
    out.extend_from_slice(gray_norm);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_preserves_flat_value() {
        let src = vec![128u8; 16 * 16];
        let out = resize_gray(&src, 16, 16, 8, 8).unwrap();
        assert_eq!(out.len(), 64);
        assert!(out.iter().all(|&v| v == 128));
    }

    #[test]
    fn resize_upscales_smoothly() {
        let src = vec![0u8; 4];
        let out = resize_gray(&src, 2, 2, 4, 4).unwrap();
        assert_eq!(out.len(), 16);
        assert!(out.iter().all(|&v| v == 0));
    }

    #[test]
    fn resize_rejects_bad_size() {
        assert!(resize_gray(&[1, 2, 3], 4, 4, 2, 2).is_err());
    }

    #[test]
    fn normalization_range() {
        let norm = normalize_gray(&[0, 128, 255]);
        assert_eq!(norm[0], -1.0);
        assert!((norm[1] - 0.003_921_568_4).abs() < 1e-6);
        assert_eq!(norm[2], 1.0);
    }

    #[test]
    fn rgb_expansion_is_channel_major() {
        let out = gray_to_rgb3(&[0.5, -0.5]);
        assert_eq!(out, vec![0.5, -0.5, 0.5, -0.5, 0.5, -0.5]);
    }
}
