use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess};

/// A face embedding vector, as produced by the recognition model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Embedding {
    pub model: String,
    pub dim: usize,
    pub values: Vec<f32>,
}

impl Embedding {
    pub fn new(model: impl Into<String>, values: Vec<f32>) -> Self {
        let dim = values.len();
        Self {
            model: model.into(),
            dim,
            values,
        }
    }

    /// Cosine similarity in [-1, 1]. Returns `None` on dimension mismatch.
    pub fn cosine(&self, other: &Self) -> Option<f32> {
        if self.dim != other.dim || self.dim == 0 {
            return None;
        }
        let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
        for (a, b) in self.values.iter().zip(&other.values) {
            let (a, b) = (f64::from(*a), f64::from(*b));
            dot += a * b;
            na += a * a;
            nb += b * b;
        }
        let denom = na.sqrt() * nb.sqrt();
        if denom <= f64::EPSILON {
            return None;
        }
        Some((dot / denom) as f32)
    }

    /// Blend `other` into `self` at the given EMA rate (the weight of the
    /// new sample, in `[0, 1]`) and renormalize to unit length, so cosine
    /// similarity keeps its usual scale. `rate = 0` returns `self`
    /// (normalized), `rate = 1` returns `other` (normalized). Used for
    /// adaptive template refinement. Returns `None` on model/dimension
    /// mismatch or a zero-norm blend.
    pub fn blend_toward(&self, other: &Self, rate: f32) -> Option<Self> {
        if self.model != other.model || self.dim != other.dim || self.dim == 0 {
            return None;
        }
        let keep = 1.0 - rate;
        let mut values: Vec<f32> = self
            .values
            .iter()
            .zip(&other.values)
            .map(|(a, b)| a * keep + b * rate)
            .collect();
        let norm: f64 = values
            .iter()
            .map(|v| f64::from(*v) * f64::from(*v))
            .sum::<f64>()
            .sqrt();
        if norm <= f64::EPSILON {
            return None;
        }
        for v in &mut values {
            *v /= norm as f32;
        }
        Some(Self {
            model: self.model.clone(),
            dim: self.dim,
            values,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.values.len() * 4);
        for v in &self.values {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(model: impl Into<String>, dim: usize, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != dim * 4 {
            return None;
        }
        let mut values = Vec::with_capacity(dim);
        for chunk in bytes.chunks_exact(4) {
            values.push(f32::from_le_bytes(chunk.try_into().ok()?));
        }
        Some(Self::new(model, values))
    }
}

/// Constant-time comparison of a cosine similarity against a threshold.
///
/// Returns true iff `score >= threshold`, without branching on the inputs.
/// This avoids leaking match proximity through timing.
pub fn constant_time_match(score: f32, threshold: f32) -> bool {
    // Map f32 bits to a monotone u32 ordering (works for negatives too),
    // then compare with constant-time less-than and negate for >=.
    let order = |v: f32| {
        let b = v.to_bits();
        if b & 0x8000_0000 != 0 {
            !b
        } else {
            b | 0x8000_0000
        }
    };
    let s = order(score);
    let t = order(threshold);
    !bool::from(ConstantTimeLess::ct_lt(&s, &t))
}

impl ConstantTimeEq for Embedding {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.dim != other.dim {
            return Choice::from(0);
        }
        let mut acc = Choice::from(1);
        for (a, b) in self.values.iter().zip(&other.values) {
            acc &= a.to_bits().ct_eq(&b.to_bits());
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_of_identical_vectors_is_one() {
        let a = Embedding::new("m", vec![1.0, 2.0, 3.0]);
        let b = Embedding::new("m", vec![1.0, 2.0, 3.0]);
        assert!((a.cosine(&b).unwrap() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_of_orthogonal_is_zero() {
        let a = Embedding::new("m", vec![1.0, 0.0]);
        let b = Embedding::new("m", vec![0.0, 1.0]);
        assert!(a.cosine(&b).unwrap().abs() < 1e-6);
    }

    #[test]
    fn cosine_dim_mismatch_is_none() {
        let a = Embedding::new("m", vec![1.0]);
        let b = Embedding::new("m", vec![1.0, 2.0]);
        assert!(a.cosine(&b).is_none());
    }

    #[test]
    fn blend_toward_interpolates_direction() {
        let a = Embedding::new("m", vec![1.0, 0.0]);
        let b = Embedding::new("m", vec![0.0, 1.0]);
        let mid = a.blend_toward(&b, 0.5).unwrap();
        // (1,0) and (0,1) blended half-way points along the diagonal.
        assert!((mid.values[0] - std::f32::consts::FRAC_1_SQRT_2).abs() < 1e-6);
        assert!((mid.values[1] - std::f32::consts::FRAC_1_SQRT_2).abs() < 1e-6);

        // Rate 0 keeps the direction of `self`; rate 1 takes `other`'s.
        let same = a.blend_toward(&b, 0.0).unwrap();
        assert!((same.cosine(&a).unwrap() - 1.0).abs() < 1e-6);
        let flipped = a.blend_toward(&b, 1.0).unwrap();
        assert!((flipped.cosine(&b).unwrap() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn blend_toward_rejects_model_or_dim_mismatch() {
        let a = Embedding::new("m", vec![1.0, 0.0]);
        assert!(a.blend_toward(&Embedding::new("n", vec![0.0, 1.0]), 0.5).is_none());
        assert!(a.blend_toward(&Embedding::new("m", vec![1.0]), 0.5).is_none());
    }

    #[test]
    fn roundtrip_serialization() {
        let a = Embedding::new("m", vec![0.5, -0.25, 1.0]);
        let bytes = a.serialize();
        let b = Embedding::from_bytes("m", 3, &bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn from_bytes_rejects_bad_length() {
        assert!(Embedding::from_bytes("m", 3, &[0u8; 7]).is_none());
    }

    #[test]
    fn constant_time_match_bounds() {
        assert!(constant_time_match(0.7, 0.6));
        assert!(!constant_time_match(0.6, 0.7));
        assert!(constant_time_match(0.6, 0.6));
        assert!(constant_time_match(-1.0, -1.0));
        assert!(!constant_time_match(-0.6, -0.5));
    }
}
