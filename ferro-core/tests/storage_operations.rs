use ferro_core::mount_cleanup::cleanup_container_mount;
use ferro_core::rootfs::construct_rootfs;
use ferro_core::rootfs_prep::prepare_container_rootfs;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tar::{Builder, Header};

#[test]
fn integration_prepares_and_cleans_container_storage_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_dir = temp.path().join("runtime");

    let layer1 = temp.path().join("layer1.tar");
    let layer2 = temp.path().join("layer2.tar");
    create_tar(&layer1, &[("etc/base.txt", "base")]);
    create_tar(&layer2, &[("etc/top.txt", "top")]);

    let prep = prepare_container_rootfs(&runtime_dir, "c-storage", &[layer1, layer2])
        .expect("rootfs prep should succeed");

    assert_eq!(prep.extracted_layer_dirs.len(), 2);
    assert!(prep.extracted_layer_dirs[0].join("etc/base.txt").exists());
    assert!(prep.extracted_layer_dirs[1].join("etc/top.txt").exists());

    fs::create_dir_all(runtime_dir.join("containers/c-storage/rootfs")).expect("create rootfs dir");
    fs::create_dir_all(runtime_dir.join("containers/c-storage/upper")).expect("create upper dir");
    fs::create_dir_all(runtime_dir.join("containers/c-storage/work")).expect("create work dir");

    cleanup_container_mount(&runtime_dir, "c-storage").expect("cleanup should succeed");
    assert!(!runtime_dir.join("containers/c-storage").exists());
}

#[test]
fn integration_constructs_rootfs_with_whiteout_layers() {
    let temp = tempfile::tempdir().expect("tempdir");
    let rootfs = temp.path().join("rootfs");

    let layer1 = temp.path().join("layer1.tar");
    let layer2 = temp.path().join("layer2.tar");

    create_tar(
        &layer1,
        &[("app/config.yml", "v1"), ("app/keep.txt", "keep")],
    );
    create_tar(
        &layer2,
        &[("app/.wh.config.yml", ""), ("app/config.yml", "v2")],
    );

    construct_rootfs(&rootfs, &[layer1, layer2]).expect("construct rootfs");

    assert_eq!(
        fs::read_to_string(rootfs.join("app/config.yml")).expect("new config"),
        "v2"
    );
    assert_eq!(
        fs::read_to_string(rootfs.join("app/keep.txt")).expect("kept file"),
        "keep"
    );
}

fn create_tar(path: &Path, entries: &[(&str, &str)]) {
    let file = fs::File::create(path).expect("create tar");
    let mut builder = Builder::new(file);

    for (entry_path, content) in entries {
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                PathBuf::from(entry_path),
                Cursor::new(content.as_bytes()),
            )
            .expect("append tar data");
    }

    builder.finish().expect("finish tar");
}
