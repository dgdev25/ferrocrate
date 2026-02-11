#[derive(Debug, Clone, Copy)]
pub struct AnomalyScore {
    pub score: f32,
    pub threshold: f32,
}

impl AnomalyScore {
    pub fn is_anomalous(&self) -> bool {
        self.score > self.threshold
    }
}

pub fn zscore(current: f32, mean: f32, stddev: f32, threshold: f32) -> AnomalyScore {
    let score = if stddev > 0.0 { (current - mean) / stddev } else { 0.0 };
    AnomalyScore { score, threshold }
}
