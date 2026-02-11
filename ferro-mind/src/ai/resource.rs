#[derive(Debug, Clone, Copy)]
pub struct ResourceSample {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ResourcePrediction {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

#[derive(Default, Debug)]
pub struct ResourcePredictor {
    window: Vec<ResourceSample>,
    max_len: usize,
}

impl ResourcePredictor {
    pub fn new(max_len: usize) -> Self {
        Self {
            window: Vec::new(),
            max_len: max_len.max(1),
        }
    }

    pub fn push(&mut self, sample: ResourceSample) {
        self.window.push(sample);
        if self.window.len() > self.max_len {
            self.window.remove(0);
        }
    }

    pub fn predict(&self) -> Option<ResourcePrediction> {
        if self.window.is_empty() {
            return None;
        }
        let mut cpu = 0.0f32;
        let mut mem = 0u64;
        for sample in &self.window {
            cpu += sample.cpu_percent;
            mem = mem.saturating_add(sample.memory_bytes);
        }
        let count = self.window.len() as f32;
        Some(ResourcePrediction {
            cpu_percent: cpu / count,
            memory_bytes: mem / self.window.len() as u64,
        })
    }
}
