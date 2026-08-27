use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

const PLACEHOLDER_MARKER: &str = "<!-- ferrocrate-dashboard-placeholder -->";
const PLACEHOLDER_MESSAGE: &str = "The dashboard UI was not bundled in this build. Run `npm ci && npm run build` in apps/ferro-desktop-ui, then rebuild ferro-cli.";

fn copy_dir(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let destination = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

fn npm_is_available() -> bool {
    Command::new("npm")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn prepare_dashboard_assets() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir_value = env::var("CARGO_MANIFEST_DIR")?;
    let manifest_dir = Path::new(&manifest_dir_value);
    let frontend_dir = manifest_dir.join("../apps/ferro-desktop-ui");
    let source_dist = frontend_dir.join("dist");
    let output_dist = Path::new(&env::var("OUT_DIR")?).join("ferrocrate-dashboard-dist");
    println!(
        "cargo:rerun-if-changed={}",
        frontend_dir.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        frontend_dir.join("package-lock.json").display()
    );
    println!("cargo:rerun-if-changed={}", source_dist.display());

    if !source_dist.is_dir()
        && env::var_os("FERROCRATE_SKIP_FRONTEND_BUILD").is_none()
        && npm_is_available()
    {
        let status = Command::new("npm")
            .args(["ci"])
            .current_dir(&frontend_dir)
            .status()?;
        if !status.success() {
            return Err("npm ci failed while building the embedded dashboard".into());
        }
        let status = Command::new("npm")
            .args(["run", "build"])
            .current_dir(&frontend_dir)
            .status()?;
        if !status.success() {
            return Err("npm run build failed while building the embedded dashboard".into());
        }
    }

    if output_dist.exists() {
        fs::remove_dir_all(&output_dist)?;
    }
    if source_dist.is_dir() {
        copy_dir(&source_dist, &output_dist)?;
    } else {
        fs::create_dir_all(&output_dist)?;
        fs::write(
            output_dist.join("index.html"),
            format!("<!doctype html><html><head><meta charset=\"utf-8\">{PLACEHOLDER_MARKER}</head><body><p>{PLACEHOLDER_MESSAGE}</p></body></html>"),
        )?;
        println!("cargo:warning=dashboard UI was not bundled: {PLACEHOLDER_MESSAGE}");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prepare_dashboard_assets()?;
    let proto_root = "../ferro-core/proto/buildkit";
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(
            config,
            &[
                format!("{proto_root}/github.com/moby/buildkit/api/services/control/control.proto"),
                format!("{proto_root}/github.com/moby/buildkit/frontend/gateway/pb/gateway.proto"),
                format!("{proto_root}/github.com/moby/buildkit/solver/errdefs/errdefs.proto"),
                format!("{proto_root}/github.com/moby/buildkit/util/apicaps/pb/caps.proto"),
            ],
            &[proto_root.to_string()],
        )?;
    println!("cargo:rerun-if-changed={proto_root}");
    Ok(())
}
