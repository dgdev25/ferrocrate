#[derive(Debug, Clone)]
pub struct GpuInfo {
    pub id: String,
    pub vram_bytes: u64,
}

pub fn select_gpu(candidates: &[GpuInfo], required_vram_bytes: u64) -> Option<GpuInfo> {
    candidates
        .iter()
        .filter(|gpu| gpu.vram_bytes >= required_vram_bytes)
        .min_by_key(|gpu| gpu.vram_bytes)
        .cloned()
}
