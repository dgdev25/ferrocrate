#[derive(Debug, Clone)]
pub struct AiConfig {
    pub enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl AiConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("FERROCRATE_AI")
            .map(|val| !(val == "0" || val.eq_ignore_ascii_case("false")))
            .unwrap_or(true);
        Self { enabled }
    }
}
