use std::env;
use std::fs;
use std::io;
use std::path::Path;

const PLACEHOLDER_MARKER: &str = "<!-- ferrocrate-dashboard-placeholder -->";
const PLACEHOLDER_MESSAGE: &str = "The fleet UI was not bundled in this build. Run `npm ci && npm run build` in apps/ferro-desktop-ui, then rebuild ferro-mgr.";

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

/// Stage the desktop UI `dist` folder into OUT_DIR for `rust_embed`, or a
/// placeholder page when it has not been built. ferro-cli's build script is
/// the one that runs npm; this crate must compile in any build order.
fn prepare_fleet_assets() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir_value = env::var("CARGO_MANIFEST_DIR")?;
    let source_dist = Path::new(&manifest_dir_value).join("../apps/ferro-desktop-ui/dist");
    let output_dist = Path::new(&env::var("OUT_DIR")?).join("ferrocrate-fleet-dist");
    println!("cargo:rerun-if-changed={}", source_dist.display());
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
        println!("cargo:warning=fleet UI was not bundled: {PLACEHOLDER_MESSAGE}");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prepare_fleet_assets()?;
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(
            config,
            &["proto/ferro/manager/v1/manager.proto"],
            &["proto"],
        )?;
    Ok(())
}
