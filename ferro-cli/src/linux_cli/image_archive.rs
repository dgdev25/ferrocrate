//! Docker-compatible image archive import and export.

use super::*;

pub(super) fn docker_save_image_archive(
    runtime_dir: &Path,
    store: &LocalImageStore,
    names: &[String],
) -> Result<Vec<u8>, String> {
    let mut manifest_entries = Vec::new();
    let mut repositories = serde_json::Map::new();
    let mut blobs = Vec::<(String, Vec<u8>)>::new();
    for (image_index, name) in names.iter().enumerate() {
        let reference = resolve_reference(store, name)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("docker: unknown image {name}"))?;
        let manifest = parse_image_manifest(&reference.manifest_json)
            .map_err(|error| format!("docker: invalid image manifest: {error}"))?;
        let config_path = resolve_config_path_with_store(runtime_dir, name, store)
            .map_err(|error| format!("docker: image config unavailable: {error}"))?
            .ok_or_else(|| "docker: image config blob is unavailable".to_string())?;
        let layer_paths = resolve_layer_paths_with_store(runtime_dir, name, store)
            .map_err(|error| format!("docker: image layer unavailable: {error}"))?;
        if layer_paths.len() != manifest.layers.len() {
            return Err("docker: image layer metadata does not match stored blobs".to_string());
        }
        let config_name = format!(
            "{}.json",
            manifest
                .config
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&manifest.config.digest)
        );
        blobs.push((
            config_name.clone(),
            std::fs::read(config_path)
                .map_err(|error| format!("docker: image export config: {error}"))?,
        ));
        let mut layers = Vec::new();
        for (layer_index, layer_path) in layer_paths.iter().enumerate() {
            // Docker's legacy save layout stores each layer in its own
            // directory. Docker load and tools that inspect saved archives
            // require the terminal filename to be exactly `layer.tar`.
            let layer_name = format!("image-{image_index}-layer-{layer_index}/layer.tar");
            let mut reader = open_decompressed_layer_reader(layer_path)
                .map_err(|error| format!("docker: image export layer: {error}"))?;
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|error| format!("docker: image export layer: {error}"))?;
            blobs.push((layer_name.clone(), bytes));
            layers.push(layer_name);
        }
        manifest_entries.push(serde_json::json!({
            "Config": config_name,
            "RepoTags": [reference.reference.clone()],
            "Layers": layers,
        }));
        if let Some(colon) = reference.reference.rfind(':') {
            if colon > reference.reference.rfind('/').unwrap_or(0) {
                repositories.insert(
                    reference.reference[..colon].to_string(),
                    serde_json::json!({&reference.reference[colon + 1..]: reference.digest}),
                );
            }
        }
    }
    let mut archive = Vec::new();
    let mut builder = tar::Builder::new(&mut archive);
    let append = |builder: &mut tar::Builder<&mut Vec<u8>>,
                  path: &str,
                  bytes: &[u8]|
     -> Result<(), String> {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .map_err(|error| format!("docker: image export {path}: {error}"))
    };
    append(
        &mut builder,
        "manifest.json",
        &serde_json::to_vec(&manifest_entries).map_err(|error| error.to_string())?,
    )?;
    append(
        &mut builder,
        "repositories",
        &serde_json::to_vec(&repositories).map_err(|error| error.to_string())?,
    )?;
    for (path, bytes) in blobs {
        append(&mut builder, &path, &bytes)?;
    }
    builder
        .finish()
        .map_err(|error| format!("docker: finish image export: {error}"))?;
    drop(builder);
    Ok(archive)
}
