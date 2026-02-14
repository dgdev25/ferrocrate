#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub cost_per_1k_tokens: f32,
    pub quality: f32,
}

#[derive(Debug, Clone)]
pub struct RoutingPolicy {
    pub min_quality: f32,
}

pub fn choose_provider<'a>(
    providers: &'a [Provider],
    policy: &RoutingPolicy,
) -> Option<&'a Provider> {
    providers
        .iter()
        .filter(|p| p.quality >= policy.min_quality)
        .min_by(|a, b| {
            // CQ-01: Handle NaN values - treat as equal to avoid panic
            a.cost_per_1k_tokens.partial_cmp(&b.cost_per_1k_tokens)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}
