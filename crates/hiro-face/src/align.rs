//! Five-landmark similarity alignment.
//!
//! Fits a 2x3 affine transform (rotation + scale + translation) mapping
//! canonical face coordinates to detected landmarks, then resamples the
//! source frame into a canonical 112x112 crop — the input layout expected
//! by ArcFace-class embedders.

/// Canonical landmark positions for a 112x112 crop (insightface norm-crop
/// layout): right eye, left eye, nose, right mouth, left mouth.
pub const CANONICAL_112: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// Solve the least-squares affine transform mapping `dst` points (canonical
/// coordinates) to `src` points (detected landmark coordinates).
/// Returns `[a, b, tx, c, d, ty]` such that
/// `sx = a*dx + b*dy + tx`, `sy = c*dx + d*dy + ty`.
pub fn fit_affine(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> [f32; 6] {
    let mut sxx = 0.0f64;
    let mut syy = 0.0f64;
    let mut sxy = 0.0f64;
    let mut sx = 0.0f64;
    let mut sy = 0.0f64;
    let mut n = 0.0f64;
    for d in dst {
        let (dx, dy) = (f64::from(d[0]), f64::from(d[1]));
        sxx += dx * dx;
        syy += dy * dy;
        sxy += dx * dy;
        sx += dx;
        sy += dy;
        n += 1.0;
    }
    // Normal matrix A^T A where A = [x y 1]:
    // [[sxx sxy sx], [sxy syy sy], [sx sy n]]
    // Solve for two right-hand sides (x targets and y targets) with
    // Cramer's rule on the 3x3 system.
    let solve3 = |a: [[f64; 3]; 3], b: [f64; 3]| -> [f64; 3] {
        let det = |m: [[f64; 3]; 3]| {
            m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
                - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
                + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
        };
        let d = det(a);
        if d.abs() < 1e-12 {
            return [0.0; 3];
        }
        let col = |j: usize| {
            let mut m = a;
            for (i, row) in m.iter_mut().enumerate() {
                row[j] = b[i];
            }
            det(m) / d
        };
        [col(0), col(1), col(2)]
    };

    let m = [[sxx, sxy, sx], [sxy, syy, sy], [sx, sy, n]];

    let mut bx_sum = [0.0f64; 3];
    let mut by_sum = [0.0f64; 3];
    for (s, d) in src.iter().zip(dst) {
        let (dx, dy) = (f64::from(d[0]), f64::from(d[1]));
        bx_sum[0] += f64::from(s[0]) * dx;
        bx_sum[1] += f64::from(s[0]) * dy;
        bx_sum[2] += f64::from(s[0]);
        by_sum[0] += f64::from(s[1]) * dx;
        by_sum[1] += f64::from(s[1]) * dy;
        by_sum[2] += f64::from(s[1]);
    }
    let rx = solve3(m, bx_sum);
    let ry = solve3(m, by_sum);
    [
        rx[0] as f32,
        rx[1] as f32,
        rx[2] as f32,
        ry[0] as f32,
        ry[1] as f32,
        ry[2] as f32,
    ]
}

/// Crop + align a grayscale frame into an `out_size` x `out_size` canonical
/// face image using the detected landmarks. Returns `None` on degenerate
/// input.
pub fn align_crop(
    luma: &[u8],
    sw: u32,
    sh: u32,
    landmarks: &[[f32; 2]; 5],
    out_size: u32,
) -> Option<Vec<u8>> {
    if sw == 0 || sh == 0 || out_size == 0 || luma.len() != (sw * sh) as usize {
        return None;
    }
    let m = fit_affine(landmarks, &CANONICAL_112);
    let (sw, sh, out) = (sw as usize, sh as usize, out_size as usize);
    let mut result = vec![0u8; out * out];
    for y in 0..out {
        let cy = (y as f32 + 0.5) * (112.0 / out as f32);
        for x in 0..out {
            let cx = (x as f32 + 0.5) * (112.0 / out as f32);
            let sx = m[0] * cx + m[1] * cy + m[2];
            let sy = m[3] * cx + m[4] * cy + m[5];
            if sx < 0.0 || sy < 0.0 || sx >= (sw - 1) as f32 || sy >= (sh - 1) as f32 {
                result[y * out + x] = 0;
                continue;
            }
            let x0 = sx.floor() as usize;
            let y0 = sy.floor() as usize;
            let x1 = (x0 + 1).min(sw - 1);
            let y1 = (y0 + 1).min(sh - 1);
            let wx = sx - x0 as f32;
            let wy = sy - y0 as f32;
            let v00 = f32::from(luma[y0 * sw + x0]);
            let v01 = f32::from(luma[y0 * sw + x1]);
            let v10 = f32::from(luma[y1 * sw + x0]);
            let v11 = f32::from(luma[y1 * sw + x1]);
            let top = v00 * (1.0 - wx) + v01 * wx;
            let bottom = v10 * (1.0 - wx) + v11 * wx;
            result[y * out + x] = (top * (1.0 - wy) + bottom * wy).round().clamp(0.0, 255.0) as u8;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_landmarks_fit_identity_transform() {
        let pts = CANONICAL_112;
        let m = fit_affine(&pts, &pts);
        assert!((m[0] - 1.0).abs() < 1e-3, "a={}", m[0]);
        assert!(m[1].abs() < 1e-3, "b={}", m[1]);
        assert!(m[2].abs() < 1e-3, "tx={}", m[2]);
        assert!(m[3].abs() < 1e-3, "c={}", m[3]);
        assert!((m[4] - 1.0).abs() < 1e-3, "d={}", m[4]);
        assert!(m[5].abs() < 1e-3, "ty={}", m[5]);
    }

    #[test]
    fn scaled_landmarks_fit_scale() {
        let scaled: [[f32; 2]; 5] = CANONICAL_112.map(|[x, y]| [x * 2.0 + 10.0, y * 2.0 + 20.0]);
        let m = fit_affine(&scaled, &CANONICAL_112);
        assert!((m[0] - 2.0).abs() < 1e-2, "a={}", m[0]);
        assert!((m[4] - 2.0).abs() < 1e-2, "d={}", m[4]);
        assert!((m[2] - 10.0).abs() < 1e-2, "tx={}", m[2]);
        assert!((m[5] - 20.0).abs() < 1e-2, "ty={}", m[5]);
    }

    #[test]
    fn align_crop_flat_image_stays_flat() {
        let luma = vec![77u8; 224 * 224];
        let out = align_crop(&luma, 224, 224, &CANONICAL_112, 112).unwrap();
        assert_eq!(out.len(), 112 * 112);
        assert!(out.iter().all(|&v| v == 77));
    }

    #[test]
    fn align_crop_rejects_bad_input() {
        assert!(align_crop(&[1, 2, 3], 4, 4, &CANONICAL_112, 112).is_none());
        assert!(align_crop(&[], 0, 0, &CANONICAL_112, 112).is_none());
    }
}
