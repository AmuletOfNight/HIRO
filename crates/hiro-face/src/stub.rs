//! Deterministic stub pipeline.
//!
//! Used by the integration test suite and for smoke-testing an install
//! without model files. Recognition is a brightness-pattern hash, not a
//! real biometric — never enable in production for anything but tests.

use hiro_core::Embedding;

use crate::{FaceHit, FacePipeline, FaceResult};

pub struct StubPipeline;

impl StubPipeline {
    pub fn new() -> Self {
        Self
    }

    fn center_blob(luma: &[u8], width: u32, height: u32) -> Option<[f32; 4]> {
        if width < 8 || height < 8 {
            return None;
        }
        let (w, h) = (width as usize, height as usize);
        let cx = w / 2;
        let cy = h / 2;
        let r = w.min(h) / 3;
        if r == 0 {
            return None;
        }
        let mut center_sum = 0u64;
        let mut center_n = 0u64;
        let mut border_sum = 0u64;
        let mut border_n = 0u64;
        for y in 0..h {
            for x in 0..w {
                let v = u64::from(luma[y * w + x]);
                let dx = x as i64 - cx as i64;
                let dy = y as i64 - cy as i64;
                if dx * dx + dy * dy < (r * r) as i64 {
                    center_sum += v;
                    center_n += 1;
                } else if x < 4 || x + 4 >= w || y < 4 || y + 4 >= h {
                    border_sum += v;
                    border_n += 1;
                }
            }
        }
        let center_mean = center_sum as f32 / center_n as f32;
        let border_mean = border_sum as f32 / border_n as f32;
        if center_mean < border_mean + 40.0 {
            return None;
        }
        let x0 = (cx.saturating_sub(r)) as f32 / w as f32;
        let y0 = (cy.saturating_sub(r)) as f32 / h as f32;
        let x1 = (cx + r).min(w - 1) as f32 / w as f32;
        let y1 = (cy + r).min(h - 1) as f32 / h as f32;
        Some([x0, y0, x1, y1])
    }
}

impl FacePipeline for StubPipeline {
    fn process(&self, luma: &[u8], width: u32, height: u32) -> FaceResult<Option<FaceHit>> {
        let bbox = match Self::center_blob(luma, width, height) {
            Some(b) => b,
            None => return Ok(None),
        };
        let (w, h) = (width as usize, height as usize);
        if luma.len() != w * h {
            return Ok(None);
        }
        let grid = 8;
        let gw = w / grid;
        let gh = h / grid;
        let mut values = Vec::with_capacity(grid * grid);
        for gy in 0..grid {
            for gx in 0..grid {
                let mut acc = 0u64;
                let mut n = 0u64;
                for y in gy * gh..(gy + 1) * gh {
                    for x in gx * gw..(gx + 1) * gw {
                        acc += u64::from(luma[y * w + x]);
                        n += 1;
                    }
                }
                let mean = acc as f32 / n.max(1) as f32;
                values.push(mean / 255.0);
            }
        }
        let mut emb = Vec::with_capacity(512);
        for _ in 0..8 {
            emb.extend_from_slice(&values);
        }
        let (cx, cy) = ((bbox[0] + bbox[2]) / 2.0, (bbox[1] + bbox[3]) / 2.0);
        let eye_y = cy - 0.15;
        let mouth_y = cy + 0.2;
        // Tiny noise-derived jitter so liveness micro-motion checks see a
        // living subject instead of a frozen set of landmarks.
        let jitter = (luma[0] as f32 + luma[w - 1] as f32) % 7.0 / 7.0 - 0.5;
        let jitter = jitter * 0.008;
        let landmarks = [
            [cx - 0.15 + jitter, eye_y],
            [cx + 0.15 - jitter, eye_y + jitter * 0.5],
            [cx + jitter * 0.5, cy],
            [cx - 0.1, mouth_y + jitter],
            [cx + 0.1, mouth_y - jitter],
        ];
        Ok(Some(FaceHit {
            embedding: Embedding::new("stub", emb),
            landmarks,
            bbox,
            det_score: 0.99,
        }))
    }

    fn name(&self) -> &str {
        "stub"
    }

    fn loaded(&self) -> bool {
        true
    }
}

impl Default for StubPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiro_hw::capture::VideoSource;
    use hiro_hw::mock::MockSource;
    use std::time::Duration;

    #[test]
    fn detects_mock_face_and_embeds_consistently() {
        let mut src = MockSource::new(64, 48, vec![2, 4]);
        src.start().unwrap();
        let p = StubPipeline::new();

        let f1 = src.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        let gray1 = f1.to_gray().unwrap();
        assert!(
            p.process(&gray1, f1.width, f1.height).unwrap().is_none(),
            "frame 1 is noise"
        );

        let f2 = src.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        let gray2 = f2.to_gray().unwrap();
        let hit2 = p.process(&gray2, f2.width, f2.height).unwrap().unwrap();

        let f3 = src.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        assert!(p
            .process(&f3.to_gray().unwrap(), f3.width, f3.height)
            .unwrap()
            .is_none());

        let f4 = src.next_frame(Duration::from_millis(10)).unwrap().unwrap();
        let hit4 = p
            .process(&f4.to_gray().unwrap(), f4.width, f4.height)
            .unwrap()
            .unwrap();

        let sim = hit2.embedding.cosine(&hit4.embedding).unwrap();
        assert!(
            sim > 0.95,
            "same-face stub embeddings should match closely: {sim}"
        );
    }
}
