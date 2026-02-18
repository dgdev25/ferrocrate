use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub struct GpuInfo {
    pub id: String,
    pub name: String,
    pub vram_total_bytes: u64,
    pub vram_free_bytes: u64,
    pub utilization_percent: f32,
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
}
