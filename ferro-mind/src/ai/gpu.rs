use serde::Serialize;
use std::collections::BTreeMap;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GpuInfo {
    pub id: String,
    pub name: String,
    pub vram_total_bytes: u64,
    pub vram_free_bytes: u64,
    pub utilization_percent: f32,
}

/// A durable-in-memory placement decision for one workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GpuReservation {
    pub request_id: String,
    pub gpu_id: String,
    pub vram_bytes: u64,
}

/// Reservation-aware GPU placement scheduler.
///
/// Discovery reports instantaneous free VRAM. This scheduler layers bounded
/// reservations over that snapshot so concurrent requests cannot each select
/// the same apparent free capacity. Reservations are process-local and must be
/// released when the workload exits; a fresh discovery should seed a new
/// scheduler after restart.
#[derive(Debug, Clone, Default)]
pub struct GpuScheduler {
    gpus: Vec<GpuInfo>,
    reservations: BTreeMap<String, GpuReservation>,
}

impl GpuScheduler {
    pub fn new(gpus: Vec<GpuInfo>) -> Self {
        Self {
            gpus,
            reservations: BTreeMap::new(),
        }
    }

    pub fn reservations(&self) -> impl Iterator<Item = &GpuReservation> {
        self.reservations.values()
    }

    pub fn available_vram_bytes(&self, gpu_id: &str) -> Option<u64> {
        let gpu = self.gpus.iter().find(|gpu| gpu.id == gpu_id)?;
        let reserved = self
            .reservations
            .values()
            .filter(|reservation| reservation.gpu_id == gpu_id)
            .map(|reservation| reservation.vram_bytes)
            .fold(0u64, u64::saturating_add);
        Some(gpu.vram_free_bytes.saturating_sub(reserved))
    }

    /// Reserve the best fitting GPU for a workload, idempotently by request ID.
    pub fn reserve(
        &mut self,
        request_id: impl Into<String>,
        required_vram_bytes: u64,
    ) -> Option<GpuReservation> {
        let request_id = request_id.into();
        if let Some(existing) = self.reservations.get(&request_id) {
            return Some(existing.clone());
        }

        let selected = self
            .gpus
            .iter()
            .filter_map(|gpu| {
                let available = self.available_vram_bytes(&gpu.id)?;
                (available >= required_vram_bytes).then_some((gpu, available))
            })
            .min_by(|(a, available_a), (b, available_b)| {
                a.utilization_percent
                    .partial_cmp(&b.utilization_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        available_a
                            .saturating_sub(required_vram_bytes)
                            .cmp(&available_b.saturating_sub(required_vram_bytes))
                    })
                    .then_with(|| a.id.cmp(&b.id))
            })?;

        let reservation = GpuReservation {
            request_id: request_id.clone(),
            gpu_id: selected.0.id.clone(),
            vram_bytes: required_vram_bytes,
        };
        self.reservations.insert(request_id, reservation.clone());
        Some(reservation)
    }

    pub fn release(&mut self, request_id: &str) -> Option<GpuReservation> {
        self.reservations.remove(request_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GpuDiscoveryError {
    #[error("failed to run discovery command: {0}")]
    Command(String),
    #[error("discovery command failed (status {status}): {stderr}")]
    CommandFailed { status: i32, stderr: String },
}

/// Discover GPUs via `nvidia-smi`.
///
/// Command can be overridden with `FERROCRATE_GPU_DISCOVERY_CMD`.
pub fn discover_gpus() -> Result<Vec<GpuInfo>, GpuDiscoveryError> {
    let cmd =
        std::env::var("FERROCRATE_GPU_DISCOVERY_CMD").unwrap_or_else(|_| "nvidia-smi".to_string());
    let output = Command::new(&cmd)
        .args([
            "--query-gpu=index,name,memory.total,memory.free,utilization.gpu",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .map_err(|err| GpuDiscoveryError::Command(err.to_string()))?;

    if !output.status.success() {
        return Err(GpuDiscoveryError::CommandFailed {
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_nvidia_smi_csv(&stdout))
}

/// Select the most suitable GPU for requested VRAM.
///
/// Ranking:
/// 1. Has enough free VRAM.
/// 2. Lower utilization preferred.
/// 3. Smaller free-VRAM surplus preferred (pack workloads tightly).
pub fn select_gpu(candidates: &[GpuInfo], required_vram_bytes: u64) -> Option<GpuInfo> {
    candidates
        .iter()
        .filter(|gpu| gpu.vram_free_bytes >= required_vram_bytes)
        .min_by(|a, b| {
            let util = a
                .utilization_percent
                .partial_cmp(&b.utilization_percent)
                .unwrap_or(std::cmp::Ordering::Equal);
            if util != std::cmp::Ordering::Equal {
                return util;
            }
            let surplus_a = a.vram_free_bytes.saturating_sub(required_vram_bytes);
            let surplus_b = b.vram_free_bytes.saturating_sub(required_vram_bytes);
            surplus_a.cmp(&surplus_b)
        })
        .cloned()
}

fn parse_nvidia_smi_csv(csv: &str) -> Vec<GpuInfo> {
    let mut gpus = Vec::new();
    for line in csv.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(',').map(|p| p.trim()).collect();
        if parts.len() < 5 {
            continue;
        }
        let total_mb = match parts[2].parse::<u64>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let free_mb = match parts[3].parse::<u64>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let utilization_percent = parts[4].parse::<f32>().unwrap_or(100.0);
        gpus.push(GpuInfo {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            vram_total_bytes: total_mb.saturating_mul(1024 * 1024),
            vram_free_bytes: free_mb.saturating_mul(1024 * 1024),
            utilization_percent,
        });
    }
    gpus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nvidia_output_extracts_gpu_fields() {
        let input = "\
0, NVIDIA RTX 4090, 24564, 22000, 7
1, NVIDIA RTX 4090, 24564, 8000, 42
";
        let gpus = parse_nvidia_smi_csv(input);
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].id, "0");
        assert_eq!(gpus[0].name, "NVIDIA RTX 4090");
        assert_eq!(gpus[0].vram_total_bytes, 24564 * 1024 * 1024);
        assert_eq!(gpus[0].vram_free_bytes, 22000 * 1024 * 1024);
        assert!((gpus[0].utilization_percent - 7.0).abs() < 0.001);
    }

    #[test]
    fn select_gpu_prefers_lower_utilization_and_tighter_fit() {
        let candidates = vec![
            GpuInfo {
                id: "0".to_string(),
                name: "gpu0".to_string(),
                vram_total_bytes: 16 * 1024 * 1024 * 1024,
                vram_free_bytes: 10 * 1024 * 1024 * 1024,
                utilization_percent: 60.0,
            },
            GpuInfo {
                id: "1".to_string(),
                name: "gpu1".to_string(),
                vram_total_bytes: 16 * 1024 * 1024 * 1024,
                vram_free_bytes: 9 * 1024 * 1024 * 1024,
                utilization_percent: 20.0,
            },
            GpuInfo {
                id: "2".to_string(),
                name: "gpu2".to_string(),
                vram_total_bytes: 24 * 1024 * 1024 * 1024,
                vram_free_bytes: 20 * 1024 * 1024 * 1024,
                utilization_percent: 20.0,
            },
        ];
        let selected = select_gpu(&candidates, 8 * 1024 * 1024 * 1024).expect("gpu selected");
        assert_eq!(selected.id, "1");
    }

    #[test]
    fn select_gpu_returns_none_when_no_gpu_fits() {
        let candidates = vec![GpuInfo {
            id: "0".to_string(),
            name: "gpu0".to_string(),
            vram_total_bytes: 8 * 1024 * 1024 * 1024,
            vram_free_bytes: 2 * 1024 * 1024 * 1024,
            utilization_percent: 10.0,
        }];
        assert!(select_gpu(&candidates, 4 * 1024 * 1024 * 1024).is_none());
    }

    #[test]
    fn scheduler_accounts_for_reservations_and_release() {
        let gpu = GpuInfo {
            id: "0".to_string(),
            name: "gpu0".to_string(),
            vram_total_bytes: 10,
            vram_free_bytes: 10,
            utilization_percent: 1.0,
        };
        let mut scheduler = GpuScheduler::new(vec![gpu]);
        let first = scheduler.reserve("a", 6).expect("first reservation");
        assert_eq!(first.gpu_id, "0");
        assert_eq!(scheduler.available_vram_bytes("0"), Some(4));
        assert!(scheduler.reserve("b", 5).is_none());
        assert_eq!(scheduler.reserve("a", 99), Some(first.clone()));
        assert_eq!(scheduler.release("a"), Some(first));
        assert_eq!(scheduler.available_vram_bytes("0"), Some(10));
    }

    #[test]
    fn scheduler_chooses_lower_utilization_then_stable_id() {
        let gpus = vec![
            GpuInfo {
                id: "b".to_string(),
                name: "b".to_string(),
                vram_total_bytes: 10,
                vram_free_bytes: 10,
                utilization_percent: 20.0,
            },
            GpuInfo {
                id: "a".to_string(),
                name: "a".to_string(),
                vram_total_bytes: 10,
                vram_free_bytes: 10,
                utilization_percent: 20.0,
            },
        ];
        let mut scheduler = GpuScheduler::new(gpus);
        assert_eq!(scheduler.reserve("request", 3).unwrap().gpu_id, "a");
    }
}
