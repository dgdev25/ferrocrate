#[derive(Debug, Clone)]
pub struct AiConfig {
    pub enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}
