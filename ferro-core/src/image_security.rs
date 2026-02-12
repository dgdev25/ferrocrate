use std::process::Command;

pub fn verify_image_signature(image: &str) -> Result<(), String> {
    if !signature_verification_enabled() {
        return Ok(());
    }
    if !command_exists("cosign") {
        return Err("signature verification requires cosign".to_string());
    }
    let key = std::env::var("FERROCRATE_SIGNATURE_KEY")
        .or_else(|_| std::env::var("COSIGN_PUBLIC_KEY"))
        .map_err(|_| "signature verification requires FERROCRATE_SIGNATURE_KEY".to_string())?;

    let output = Command::new("cosign")
        .args(["verify", "--key", &key, image])
        .output()
        .map_err(|err| format!("cosign: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cosign verify failed: {}", stderr.trim()));
    }
    Ok(())
}

fn signature_verification_enabled() -> bool {
    std::env::var("FERROCRATE_SIGNATURE_VERIFY")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn command_exists(bin: &str) -> bool {
    Command::new(bin).arg("--version").output().is_ok()
}
