// Adapted from block/buzz (Apache-2.0), desktop/src-tauri/src/webkit_rendering.rs.
//! Select WebKitGTK's stable shared-memory rendering path before WebKit starts.

use std::path::Path;

const FORCE_SHM: &str = "WEBKIT_DMABUF_RENDERER_FORCE_SHM";
const DISABLE_COMPOSITING: &str = "WEBKIT_DISABLE_COMPOSITING_MODE";

pub fn apply() -> Result<(), String> {
    let safe = std::env::args_os().any(|arg| arg == "--safe-rendering");
    let appimage = std::env::var_os("APPIMAGE").is_some();
    let nvidia = nvidia_gpu(Path::new("/sys/class/drm"));
    let owned = [FORCE_SHM, "WEBKIT_DISABLE_DMABUF_RENDERER", DISABLE_COMPOSITING];
    if let Some(name) = owned.iter().find(|name| std::env::var_os(name).is_some()) {
        if safe {
            return Err(format!("--safe-rendering conflicts with user-set {name}; unset it or remove the flag"));
        }
        eprintln!("ferro-desktop-ui: WebKit rendering mode=user-override");
        return Ok(());
    }
    if safe || appimage || nvidia {
        std::env::set_var(FORCE_SHM, "1");
        if safe {
            std::env::set_var(DISABLE_COMPOSITING, "1");
        }
        let mode = if safe { "safe" } else { "shared-memory" };
        eprintln!("ferro-desktop-ui: WebKit rendering mode={mode}");
    } else {
        eprintln!("ferro-desktop-ui: WebKit rendering mode=automatic");
    }
    Ok(())
}

fn nvidia_gpu(root: &Path) -> bool {
    std::fs::read_dir(root).is_ok_and(|entries| entries.flatten().any(|entry| {
        std::fs::read_to_string(entry.path().join("device/vendor"))
            .is_ok_and(|vendor| vendor.trim().eq_ignore_ascii_case("0x10de"))
    }))
}
