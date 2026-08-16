//! ONNX Runtime pipeline: SCRFD detection + ArcFace-class embedding.

use std::sync::Mutex;

use hiro_core::config::RecognitionConfig;
use hiro_core::Embedding;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;

use crate::align::align_crop;
use crate::models::Manifest;
use crate::preprocess::{gray_to_rgb3, normalize_gray, resize_gray};
use crate::{FaceError, FaceHit, FacePipeline, FaceResult};

/// Anchor strides of the SCRFD detection branches.
const STRIDES: [usize; 3] = [8, 16, 32];
const DET_THRESHOLD: f32 = 0.5;
const NMS_IOU: f32 = 0.4;
const DET_DEFAULT_INPUT: u32 = 640;
const EMB_DEFAULT_INPUT: u32 = 112;

struct Detection {
    score: f32,
    bbox: [f32; 4],
    landmarks: [[f32; 2]; 5],
}

pub struct OnnxPipeline {
    detector: Mutex<Session>,
    embedder: Mutex<Session>,
    det_input_name: String,
    det_input_size: u32,
    emb_input_name: String,
    emb_input_size: u32,
    model_name: String,
}

impl OnnxPipeline {
    pub fn new(config: &RecognitionConfig) -> FaceResult<Self> {
        let manifest = Manifest::builtin()?;
        manifest
            .verify_all(&config.model_dir)
            .map_err(|e| FaceError::Integrity(e.to_string()))?;

        let det = manifest.entry("detector", &config.detector)?;
        let emb = manifest.entry("embedder", &config.embedder)?;

        let det_path = config.model_dir.join(&det.file);
        let emb_path = config.model_dir.join(&emb.file);

        let detector = load_session(&det_path)?;
        let embedder = load_session(&emb_path)?;

        let det_input_name = session_input_name(&detector, 0)?;
        let emb_input_name = session_input_name(&embedder, 0)?;

        let det_input_size = det.input_w.unwrap_or(DET_DEFAULT_INPUT);
        let emb_input_size = emb.input_w.unwrap_or(EMB_DEFAULT_INPUT);

        Ok(Self {
            detector: Mutex::new(detector),
            embedder: Mutex::new(embedder),
            det_input_name,
            det_input_size,
            emb_input_name,
            emb_input_size,
            model_name: config.embedder.clone(),
        })
    }

    fn run_detector(&self, luma: &[u8], width: u32, height: u32) -> FaceResult<Vec<Detection>> {
        let size = self.det_input_size;
        let resized = resize_gray(luma, width, height, size, size)?;
        // SCRFD expects [-1, 1]: x / 127.5 - 1.
        let norm: Vec<f32> = resized
            .iter()
            .map(|&v| f32::from(v) / 127.5 - 1.0)
            .collect();
        let rgb3 = gray_to_rgb3(&norm);

        let mut session = self
            .detector
            .lock()
            .map_err(|_| FaceError::Pipeline("detector session poisoned".into()))?;
        let tensor = Tensor::from_array((vec![1i64, 3, size as i64, size as i64], rgb3))
            .map_err(|e| FaceError::Pipeline(format!("cannot build detector input: {e}")))?;
        let outputs = session
            .run(ort::inputs![self.det_input_name.as_str() => tensor])
            .map_err(|e| FaceError::Pipeline(format!("detector run failed: {e}")))?;

        let mut score_maps: Vec<Vec<f32>> = Vec::new();
        let mut bbox_maps: Vec<Vec<f32>> = Vec::new();
        let mut kps_maps: Vec<Vec<f32>> = Vec::new();
        let mut score_meta: Vec<[usize; 3]> = Vec::new(); // [anchors, channels, cells]
        let mut bbox_meta: Vec<[usize; 3]> = Vec::new();
        let mut kps_meta: Vec<[usize; 3]> = Vec::new();

        // Pass 1: collect every plausible interpretation of each output.
        let mut candidate_lists: Vec<Vec<BranchKind>> = Vec::new();
        let mut tensor_data: Vec<(Vec<f32>, Vec<usize>)> = Vec::new();
        for (_name, value) in outputs.iter() {
            let Ok((shape, data)) = value.try_extract_tensor::<f32>() else {
                continue;
            };
            let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
            let total: usize = dims.iter().product();
            let branches = classify_branch_set(total);
            if branches.is_empty() {
                log::debug!("branch output skipped: shape={dims:?} total={total}");
                continue;
            }
            tensor_data.push((data.to_vec(), dims));
            candidate_lists.push(branches);
        }

        // Pass 2: global assignment - the true export claims each
        // (kind, cells) exactly once. Target cells come from outputs that
        // have a single interpretation (the keypoint branches).
        let target_cells: Vec<usize> = candidate_lists
            .iter()
            .filter(|c| c.len() == 1)
            .map(|c| c[0].cells)
            .collect();
        let resolved = assign_branches(&candidate_lists, &target_cells);

        // Pass 3: group outputs by resolved kind, normalizing flattened
        // rank-2 [rows, channels] outputs to channel-major [channels, rows]
        // so the decode path is uniform.
        for ((data, dims), branch) in tensor_data.iter().zip(resolved) {
            let rows = if dims.len() == 2 {
                dims[0]
            } else {
                branch.anchors * branch.cells
            };
            let channels = if dims.len() == 2 {
                dims[1]
            } else {
                branch.channels
            };
            let mut norm = data.clone();
            if dims.len() == 2 {
                norm = transpose_interleaved(data, rows, channels);
            }
            match branch.kind {
                Kind::Score => {
                    score_meta.push([branch.anchors, branch.channels, branch.cells]);
                    score_maps.push(norm);
                }
                Kind::Bbox => {
                    bbox_meta.push([branch.anchors, branch.channels, branch.cells]);
                    bbox_maps.push(norm);
                }
                Kind::Kps => {
                    kps_meta.push([branch.anchors, branch.channels, branch.cells]);
                    kps_maps.push(norm);
                }
            }
        }

        decode_scrfd(
            size as usize,
            &score_maps,
            &bbox_maps,
            &kps_maps,
            &score_meta,
            &bbox_meta,
            &kps_meta,
        )
    }

    fn run_embedder(&self, crop: &[u8]) -> FaceResult<Vec<f32>> {
        let size = self.emb_input_size;
        let resized = resize_gray(crop, size, size, size, size)?;
        let norm = normalize_gray(&resized);
        let rgb3 = gray_to_rgb3(&norm);

        let mut session = self
            .embedder
            .lock()
            .map_err(|_| FaceError::Pipeline("embedder session poisoned".into()))?;
        let tensor = Tensor::from_array((vec![1i64, 3, size as i64, size as i64], rgb3))
            .map_err(|e| FaceError::Pipeline(format!("cannot build embedder input: {e}")))?;
        let outputs = session
            .run(ort::inputs![self.emb_input_name.as_str() => tensor])
            .map_err(|e| FaceError::Pipeline(format!("embedder run failed: {e}")))?;

        for (_, value) in outputs.iter() {
            if let Ok((_, data)) = value.try_extract_tensor::<f32>() {
                return Ok(data.to_vec());
            }
        }
        Err(FaceError::Pipeline(
            "embedder produced no float output".into(),
        ))
    }
}

/// One candidate box as reported by the detector (diagnostic API).
#[derive(Debug, Clone)]
pub struct DetBox {
    pub score: f32,
    pub bbox: [f32; 4],
}

impl OnnxPipeline {
    /// Diagnostic: run only the detector and return all surviving
    /// candidates. Used for threshold tuning and hardware bring-up.
    pub fn detect(&self, luma: &[u8], width: u32, height: u32) -> FaceResult<Vec<DetBox>> {
        let dets = self.run_detector(luma, width, height)?;
        Ok(dets
            .into_iter()
            .map(|d| DetBox {
                score: d.score,
                bbox: d.bbox,
            })
            .collect())
    }

    /// Diagnostic: raw pre-NMS candidates with their spatial provenance.
    #[doc(hidden)]
    pub fn detect_debug(
        &self,
        luma: &[u8],
        width: u32,
        height: u32,
    ) -> FaceResult<Vec<(f32, [f32; 4])>> {
        let dets = self.run_detector(luma, width, height)?;
        Ok(dets.into_iter().map(|d| (d.score, d.bbox)).collect())
    }

    /// Diagnostic: per-output raw maxima with the resolved branch kind.
    /// Reveals how far from detection the model is and whether the branch
    /// assignment is correct.
    pub fn raw_score_stats(&self, luma: &[u8], width: u32, height: u32) -> FaceResult<Vec<f32>> {
        self.raw_score_stats_norm(luma, width, height, 0)
    }

    /// Like [`Self::raw_score_stats`] but with a selectable input
    /// normalization for bring-up debugging:
    /// 0 = x/127.5-1, 1 = x/255, 2 = (x/255-0.5)/0.5, 3 = (x-127.5)/128.
    pub fn raw_score_stats_norm(
        &self,
        luma: &[u8],
        width: u32,
        height: u32,
        mode: u8,
    ) -> FaceResult<Vec<f32>> {
        let size = self.det_input_size;
        let resized = resize_gray(luma, width, height, size, size)?;
        let norm: Vec<f32> = resized
            .iter()
            .map(|&v| {
                let x = f32::from(v);
                match mode {
                    1 => x / 255.0,
                    2 => (x / 255.0 - 0.5) / 0.5,
                    3 => (x - 127.5) / 128.0,
                    _ => x / 127.5 - 1.0,
                }
            })
            .collect();
        let rgb3 = gray_to_rgb3(&norm);

        let mut session = self
            .detector
            .lock()
            .map_err(|_| FaceError::Pipeline("detector session poisoned".into()))?;
        let tensor = Tensor::from_array((vec![1i64, 3, size as i64, size as i64], rgb3))
            .map_err(|e| FaceError::Pipeline(format!("cannot build detector input: {e}")))?;
        let outputs = session
            .run(ort::inputs![self.det_input_name.as_str() => tensor])
            .map_err(|e| FaceError::Pipeline(format!("detector run failed: {e}")))?;

        let mut candidate_lists: Vec<Vec<BranchKind>> = Vec::new();
        let mut tensors: Vec<(String, Vec<f32>, Vec<usize>)> = Vec::new();
        for (name, value) in outputs.iter() {
            let Ok((shape, data)) = value.try_extract_tensor::<f32>() else {
                continue;
            };
            let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
            let total: usize = dims.iter().product();
            let branches = classify_branch_set(total);
            if branches.is_empty() {
                continue;
            }
            tensors.push((name.to_string(), data.to_vec(), dims));
            candidate_lists.push(branches);
        }
        let target_cells: Vec<usize> = candidate_lists
            .iter()
            .filter(|c| c.len() == 1)
            .map(|c| c[0].cells)
            .collect();
        let resolved = assign_branches(&candidate_lists, &target_cells);

        let mut stats = Vec::new();
        for ((name, data, dims), branch) in tensors.iter().zip(resolved) {
            let rows = if dims.len() == 2 {
                dims[0]
            } else {
                branch.anchors * branch.cells
            };
            let channels = if dims.len() == 2 {
                dims[1]
            } else {
                branch.channels
            };
            let norm = if dims.len() == 2 {
                transpose_interleaved(data, rows, channels)
            } else {
                data.clone()
            };
            let num_rows = rows;
            let kind = match branch.kind {
                Kind::Score => "score",
                Kind::Bbox => "bbox",
                Kind::Kps => "kps",
            };
            let mut max_v = f32::MIN;
            let mut min_v = f32::MAX;
            let mut argmax = 0usize;
            for c in 0..channels.min(2) {
                for i in 0..num_rows {
                    let v = norm[c * num_rows + i];
                    if v > max_v {
                        max_v = v;
                        argmax = i;
                    }
                    if v < min_v {
                        min_v = v;
                    }
                }
            }
            // Distribution of the first and second halves (channels or
            // anchors are laid out as contiguous blocks in channel-major
            // form).
            let half = num_rows;
            let (mut h0, mut h1, mut h0m, mut h1m) = (f32::MIN, f32::MIN, f32::MAX, f32::MAX);
            if norm.len() >= 2 * half {
                for i in 0..half {
                    let a = norm[i];
                    h0 = h0.max(a);
                    h0m = h0m.min(a);
                    let b = norm[half + i];
                    h1 = h1.max(b);
                    h1m = h1m.min(b);
                }
            } else {
                (h0, h0m, h1, h1m) = (f32::MIN, f32::MAX, f32::MIN, f32::MAX);
            }
            stats.push(max_v);
            eprintln!(
                "  [{kind}] {name}: channels={channels} rows={num_rows} min={min_v:.3} max={max_v:.3} \
                 half0=[{h0m:.3}..{h0:.3}] half1=[{h1m:.3}..{h1:.3}] argmax={argmax}"
            );
        }
        Ok(stats)
    }
}

impl FacePipeline for OnnxPipeline {
    fn process(&self, luma: &[u8], width: u32, height: u32) -> FaceResult<Option<FaceHit>> {
        let dets = self.run_detector(luma, width, height)?;
        let Some(best) = dets.first() else {
            return Ok(None);
        };

        // Landmarks are normalized [0,1]; convert to frame pixels.
        let mut landmarks_px = best.landmarks;
        for lm in &mut landmarks_px {
            lm[0] *= width as f32;
            lm[1] *= height as f32;
        }
        let Some(crop) = align_crop(luma, width, height, &landmarks_px, self.emb_input_size) else {
            return Ok(None);
        };
        let values = self.run_embedder(&crop)?;

        Ok(Some(FaceHit {
            embedding: Embedding::new(&self.model_name, values),
            landmarks: best.landmarks,
            bbox: best.bbox,
            det_score: best.score,
        }))
    }

    fn name(&self) -> &str {
        "onnx"
    }

    fn loaded(&self) -> bool {
        true
    }
}

/// Classify an SCRFD-family branch output by its element count.
///
/// SCRFD exports come in two flavors per stride: 1 anchor per cell, or
/// 2 anchors per cell (the antelope/auraface 9-output exports use 2).
/// Branch kinds are identified by channel count: scores 1 (or 2 for the
/// pos/neg form), boxes 4, keypoints 10. The per-anchor cell count must
/// be a perfect square. Returns `(anchors, channels, cells)`.
pub fn classify_branch(total: usize) -> Option<(usize, usize, usize)> {
    for (anchors, channels) in [
        (1usize, 1usize),
        (2, 1),
        (1, 2),
        (1, 4),
        (2, 4),
        (1, 10),
        (2, 10),
    ] {
        let per = anchors * channels;
        if !total.is_multiple_of(per) {
            continue;
        }
        let cells = total / per;
        let side = (cells as f64).sqrt();
        if side.fract() == 0.0 && cells > 0 {
            return Some((anchors, channels, cells));
        }
    }
    None
}

/// Test-only alias to satisfy the integration test import.
#[doc(hidden)]
pub fn classify_branch_pub(total: usize) -> Option<(usize, usize, usize)> {
    classify_branch(total)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Score,
    Bbox,
    Kps,
}

/// A single candidate interpretation of a branch output.
#[derive(Debug, Clone, Copy)]
struct BranchKind {
    kind: Kind,
    anchors: usize,
    channels: usize,
    cells: usize,
}

/// All square-cell interpretations of `total`. Ambiguities are resolved by
/// [`resolve_branch`] against the whole output set.
fn classify_branch_set(total: usize) -> Vec<BranchKind> {
    let mut out = Vec::new();
    for (kind, channels) in [
        (Kind::Score, 1usize),
        (Kind::Score, 2),
        (Kind::Bbox, 4),
        (Kind::Kps, 10),
    ] {
        for anchors in [1usize, 2] {
            let per = anchors * channels;
            if !total.is_multiple_of(per) {
                continue;
            }
            let cells = total / per;
            let side = (cells as f64).sqrt();
            if side.fract() == 0.0 && cells > 0 {
                out.push(BranchKind {
                    kind,
                    anchors,
                    channels,
                    cells,
                });
            }
        }
    }
    out
}

/// Convert a flattened `[rows, channels]` buffer (channel innermost) to
/// channel-major `[channels, rows]` ordering.
fn transpose_interleaved(data: &[f32], rows: usize, channels: usize) -> Vec<f32> {
    debug_assert_eq!(data.len(), rows * channels);
    let mut out = vec![0.0f32; rows * channels];
    for r in 0..rows {
        for c in 0..channels {
            out[c * rows + r] = data[r * channels + c];
        }
    }
    out
}

/// Assign a definite kind to each output. The true model emits exactly one
/// branch per (kind, cells) triple, so this is a small exact-cover
/// backtracking over the plausible interpretations.
fn assign_branches(candidate_lists: &[Vec<BranchKind>], target_cells: &[usize]) -> Vec<BranchKind> {
    let mut out: Vec<BranchKind> = Vec::new();
    let mut claimed: std::collections::HashSet<(Kind, usize)> = std::collections::HashSet::new();

    fn backtrack(
        lists: &[Vec<BranchKind>],
        target: &[usize],
        claimed: &mut std::collections::HashSet<(Kind, usize)>,
        out: &mut Vec<BranchKind>,
    ) -> bool {
        let idx = out.len();
        if idx == lists.len() {
            return true;
        }
        for cand in &lists[idx] {
            if !target.is_empty() && !target.contains(&cand.cells) {
                continue;
            }
            if claimed.contains(&(cand.kind, cand.cells)) {
                continue;
            }
            claimed.insert((cand.kind, cand.cells));
            out.push(*cand);
            if backtrack(lists, target, claimed, out) {
                return true;
            }
            out.pop();
            claimed.remove(&(cand.kind, cand.cells));
        }
        false
    }

    if !backtrack(candidate_lists, target_cells, &mut claimed, &mut out) {
        // Fallback: pick each output's first square-cell candidate.
        out = candidate_lists.iter().map(|c| c[0]).collect();
    }
    out
}

fn load_session(path: &std::path::Path) -> FaceResult<Session> {
    let session = Session::builder()
        .map_err(|e| FaceError::Pipeline(format!("cannot create session builder: {e}")))?
        .with_optimization_level(GraphOptimizationLevel::Level1)
        .map_err(|e| FaceError::Pipeline(format!("cannot set optimization level: {e}")))?
        .with_intra_threads(4)
        .map_err(|e| FaceError::Pipeline(format!("cannot set thread count: {e}")))?
        .commit_from_file(path)
        .map_err(|e| FaceError::Pipeline(format!("cannot load {}: {e}", path.display())))?;
    Ok(session)
}

fn session_input_name(session: &Session, index: usize) -> FaceResult<String> {
    session
        .inputs()
        .get(index)
        .map(|o| o.name().to_string())
        .ok_or_else(|| FaceError::Pipeline(format!("session has no input #{index}")))
}

fn decode_scrfd(
    input_size: usize,
    score_maps: &[Vec<f32>],
    bbox_maps: &[Vec<f32>],
    kps_maps: &[Vec<f32>],
    score_dims: &[[usize; 3]],
    _bbox_dims: &[[usize; 3]],
    _kps_dims: &[[usize; 3]],
) -> FaceResult<Vec<Detection>> {
    if score_maps.len() != bbox_maps.len() || score_maps.len() != kps_maps.len() {
        return Err(FaceError::Pipeline(
            "SCRFD output groups are unbalanced; unexpected model export".into(),
        ));
    }
    let mut dets: Vec<Detection> = Vec::new();

    // Larger feature maps correspond to smaller strides. Order branches by
    // map size so stride association survives renamed/reshuffled exports.
    let mut order: Vec<usize> = (0..score_maps.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(score_dims[i][2]));

    for (pos, i) in order.iter().enumerate() {
        let stride = STRIDES.get(pos).copied().unwrap_or(STRIDES[2]);
        let Some(score) = score_maps.get(*i) else {
            continue;
        };
        let Some(bbox) = bbox_maps.get(*i) else {
            continue;
        };
        let Some(kps) = kps_maps.get(*i) else {
            continue;
        };
        let sdims = score_dims[*i];
        let (anchors, score_c, cells) = (sdims[0], sdims[1], sdims[2]);
        let h = (cells as f64).sqrt() as usize;
        let w = h;
        if h == 0 || h * w != cells {
            continue;
        }
        let num_rows = anchors * cells;
        let two_channel = score_c == 2;
        let s = stride as f32;

        for row in 0..num_rows {
            // Flat [anchors*cells] rows are interleaved (cell-major, anchor
            // innermost), matching insightface's center construction:
            // row = cell*anchors + anchor.
            let cell = row / anchors;
            let iy = cell / w;
            let ix = cell % w;
            // The score branches of this export are already post-sigmoid
            // confidences; threshold them directly (no second sigmoid).
            let conf = if two_channel {
                score[row] - score[row + num_rows]
            } else {
                score[row]
            };
            if conf <= DET_THRESHOLD {
                continue;
            }
            let cx = ix as f32 * s;
            let cy = iy as f32 * s;
            let dx = bbox[row];
            let dy = bbox[row + num_rows];
            let dw = bbox[row + 2 * num_rows];
            let dh = bbox[row + 3 * num_rows];
            let x0 = cx - dx * s;
            let y0 = cy - dy * s;
            let x1 = cx + dw * s;
            let y1 = cy + dh * s;
            if x0 >= x1 || y0 >= y1 {
                continue;
            }
            let mut landmarks = [[0.0f32; 2]; 5];
            for k in 0..5 {
                let kx = kps[row + 2 * k * num_rows];
                let ky = kps[row + (2 * k + 1) * num_rows];
                landmarks[k] = [cx + kx * s, cy + ky * s];
            }
            let n = input_size as f32;
            dets.push(Detection {
                score: conf,
                bbox: [x0 / n, y0 / n, x1 / n, y1 / n],
                landmarks: landmarks.map(|[x, y]| [x / n, y / n]),
            });
        }
    }

    dets.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let kept = nms(&dets, NMS_IOU);
    Ok(kept)
}

fn nms(dets: &[Detection], iou_threshold: f32) -> Vec<Detection> {
    let mut kept: Vec<Detection> = Vec::new();
    for det in dets {
        let overlaps = kept.iter().any(|k| iou(&det.bbox, &k.bbox) > iou_threshold);
        if !overlaps {
            kept.push(Detection {
                score: det.score,
                bbox: det.bbox,
                landmarks: det.landmarks,
            });
        }
    }
    kept
}

fn iou(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    let x0 = a[0].max(b[0]);
    let y0 = a[1].max(b[1]);
    let x1 = a[2].min(b[2]);
    let y1 = a[3].min(b[3]);
    let inter = (x1 - x0).max(0.0) * (y1 - y0).max(0.0);
    let area_a = (a[2] - a[0]) * (a[3] - a[1]);
    let area_b = (b[2] - b[0]) * (b[3] - b[1]);
    let union = area_a + area_b - inter;
    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iou_basics() {
        let a = [0.0, 0.0, 1.0, 1.0];
        let b = [0.5, 0.5, 1.5, 1.5];
        assert!((iou(&a, &b) - 0.25 / 1.75).abs() < 1e-6);
        let c = [2.0, 2.0, 3.0, 3.0];
        assert_eq!(iou(&a, &c), 0.0);
    }

    #[test]
    fn nms_keeps_best() {
        let mk = |score: f32, bbox: [f32; 4]| Detection {
            score,
            bbox,
            landmarks: [[0.0; 2]; 5],
        };
        let dets = vec![
            mk(0.9, [0.0, 0.0, 0.5, 0.5]),
            mk(0.8, [0.01, 0.01, 0.51, 0.51]),
            mk(0.7, [3.0, 3.0, 3.5, 3.5]),
        ];
        let kept = nms(&dets, 0.5);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].score, 0.9);
        assert_eq!(kept[1].score, 0.7);
    }

    #[test]
    fn decode_rejects_unbalanced_groups() {
        assert!(decode_scrfd(640, &[vec![0.0; 4]], &[], &[], &[[1, 1, 4]], &[], &[]).is_err());
    }
}
