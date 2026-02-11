// Adapted from MIT-licensed ruvector-core (https://github.com/ruvnet/ruvector)

use crate::ruv::error::{RuvError, Result};
use crate::ruv::types::DistanceMetric;

#[inline]
pub fn distance(a: &[f32], b: &[f32], metric: DistanceMetric) -> Result<f32> {
    if a.len() != b.len() {
        return Err(RuvError::DimensionMismatch {
            expected: a.len(),
            actual: b.len(),
        });
    }

    let out = match metric {
        DistanceMetric::Euclidean => euclidean_distance(a, b),
        DistanceMetric::Cosine => cosine_distance(a, b),
        DistanceMetric::DotProduct => dot_product_distance(a, b),
        DistanceMetric::Manhattan => manhattan_distance(a, b),
    };
    Ok(out)
}

#[inline]
pub fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y) * (x - y))
        .sum::<f32>()
        .sqrt()
}

#[inline]
pub fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a > 1e-8 && norm_b > 1e-8 {
        1.0 - (dot / (norm_a * norm_b))
    } else {
        1.0
    }
}

#[inline]
pub fn dot_product_distance(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    -dot
}

#[inline]
pub fn manhattan_distance(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).sum()
}

pub fn batch_distances(
    query: &[f32],
    vectors: &[Vec<f32>],
    metric: DistanceMetric,
) -> Result<Vec<f32>> {
    vectors.iter().map(|v| distance(query, v, metric)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn euclidean_matches_expected() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![4.0, 5.0, 6.0];
        let dist = euclidean_distance(&a, &b);
        assert!((dist - 5.196).abs() < 0.01);
    }

    #[test]
    fn cosine_identical_is_zeroish() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![1.0, 2.0, 3.0];
        let dist = cosine_distance(&a, &b);
        assert!(dist < 0.01);
    }

    #[test]
    fn dot_product_distance_negates() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![4.0, 5.0, 6.0];
        let dist = dot_product_distance(&a, &b);
        assert!((dist + 32.0).abs() < 0.01);
    }

    #[test]
    fn manhattan_distance_matches() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![4.0, 5.0, 6.0];
        let dist = manhattan_distance(&a, &b);
        assert!((dist - 9.0).abs() < 0.01);
    }

    #[test]
    fn batch_distances_respects_dimension() {
        let query = vec![1.0, 2.0];
        let vectors = vec![vec![1.0, 2.0], vec![2.0, 3.0]];
        let res = batch_distances(&query, &vectors, DistanceMetric::Euclidean).unwrap();
        assert_eq!(res.len(), 2);
    }
}
