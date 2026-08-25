use std::path::{Path, PathBuf};

const PLACEHOLDER: &str = "FERROCRATE NON-BUNDLE SIDECAR PLACEHOLDER\nRun scripts/bundle-sidecars.sh before tauri build.\n";

fn main() {
    stage_non_bundle_placeholders();
    tauri_build::build()
}

fn stage_non_bundle_placeholders() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let target = std::env::var("TARGET").expect("Cargo target triple");
    let extension = if target.contains("windows") { ".exe" } else { "" };
    let directory = manifest.join("binaries");
    std::fs::create_dir_all(&directory).expect("create sidecar placeholder directory");

    for name in ["ferrocrate", "ferro-desktop"] {
        let path = directory.join(format!("{name}-{target}{extension}"));
        if !path.exists() {
            write_placeholder(&path);
        }
    }
}

fn write_placeholder(path: &Path) {
    std::fs::write(path, PLACEHOLDER).expect("write non-bundle sidecar placeholder");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("mark non-bundle sidecar placeholder executable");
    }
}
