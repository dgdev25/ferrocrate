//! RVF native container image format.
//!
//! `.rvf` is a flat binary container with named typed segments:
//!
//! ```text
//! [magic: b"RVF1"][version: u8][count: u32-LE]
//! ( [type: u8][length: u64-LE][payload: bytes] ) * count
//! ```
//!
//! Segments are written in order; readers must tolerate unknown types.
//! The format is AI-native: it can embed vector models (SEG_VEC) alongside
//! the container layer, enabling zero-pull inference at runtime.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Magic bytes at the start of every `.rvf` file.
pub const RVF_MAGIC: &[u8; 4] = b"RVF1";

/// Current format version encoded in the header.
pub const RVF_FORMAT_VERSION: u8 = 1;

/// Maximum allowed segment payload (512 MiB). Prevents OOM on malformed input.
pub const MAX_SEGMENT_PAYLOAD: usize = 512 * 1024 * 1024;

// ── Segment type constants ────────────────────────────────────────────────────

/// JSON-serialised `FerroImageManifest`.
pub const SEG_MANIFEST: u8 = 0x01;
/// Embedded vector / embedding model bytes.
pub const SEG_VEC: u8 = 0x02;
/// Overlay model bytes (fine-tuned adapter weights).
pub const SEG_OVERLAY: u8 = 0x03;
/// Compressed container layer tar bytes.
pub const SEG_LAYER: u8 = 0x04;
/// Attestation / witness bytes (reserved).
pub const SEG_WITNESS: u8 = 0x0D;
/// Kernel binary (reserved for rvf-kernel integration).
pub const SEG_KERNEL: u8 = 0x0E;
/// eBPF program bytes (reserved).
pub const SEG_EBPF: u8 = 0x0F;
/// Crypto metadata / post-quantum signature (reserved).
pub const SEG_CRYPTO: u8 = 0x10;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Segment inside an `.rvf` file.
#[derive(Debug, Clone)]
pub struct RvfSegment {
    pub seg_type: u8,
    pub payload: Vec<u8>,
}

/// A validated RVF image containing its manifest and segments.
#[derive(Debug, Clone)]
pub struct RvfImage {
    pub manifest: FerroImageManifest,
    pub segments: Vec<RvfSegment>,
}

/// Manifest embedded in every `.rvf` image as `SEG_MANIFEST`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FerroImageManifest {
    pub name: String,
    pub tag: String,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub arch: String,
    pub os: String,
    pub created_at: String,
    pub format_version: u8,
    pub layer_digest: String,
    pub layer_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_model_type: Option<String>,
}

/// Parameters for `build_rvf_image`.
pub struct RvfBuildParams<'a> {
    /// Populated manifest (layer_size will be overwritten from the actual bytes).
    pub manifest: FerroImageManifest,
    /// OCI digest of the layer blob (e.g. `"sha256:abcd..."`).
    pub layer_digest: &'a str,
    /// Runtime directory used to locate stored layer blobs.
    pub runtime_dir: &'a Path,
    /// Optional path to a vector/embedding model to embed as `SEG_VEC`.
    pub embed_model_path: Option<&'a Path>,
    /// Destination path for the output `.rvf` file.
    pub output_path: &'a Path,
}

/// Result of a successful `build_rvf_image` call.
#[derive(Debug)]
pub struct RvfBuildResult {
    pub output_path: PathBuf,
    /// SHAKE256/256 digest of the complete `.rvf` file (hex-encoded).
    pub file_digest: String,
    pub file_size: u64,
    pub segment_count: usize,
}

/// Errors produced by RVF format operations.
#[derive(Debug, Error)]
pub enum RvfError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid RVF magic bytes")]
    InvalidMagic,
    #[error("unsupported RVF version: {0}")]
    UnsupportedVersion(u8),
    #[error("manifest segment missing")]
    ManifestMissing,
    #[error("layer segment missing")]
    LayerMissing,
    #[error("RVF layer size mismatch: manifest={expected}, actual={actual}")]
    LayerSizeMismatch { expected: u64, actual: u64 },
    #[error("RVF layer digest mismatch: expected={expected}, actual={actual}")]
    LayerDigestMismatch { expected: String, actual: String },
    #[error("duplicate segment type: 0x{0:02x}")]
    DuplicateSegment(u8),
    #[error("segment payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// ── Core format I/O ───────────────────────────────────────────────────────────

/// Serialise `segments` into the RVF binary format.
pub fn write_rvf<W: Write>(writer: &mut W, segments: &[RvfSegment]) -> Result<(), RvfError> {
    let mut seen = HashSet::with_capacity(segments.len());
    for segment in segments {
        if segment.payload.len() > MAX_SEGMENT_PAYLOAD {
            return Err(RvfError::PayloadTooLarge(segment.payload.len()));
        }
        if !seen.insert(segment.seg_type) {
            return Err(RvfError::DuplicateSegment(segment.seg_type));
        }
    }
    writer.write_all(RVF_MAGIC)?;
    writer.write_all(&[RVF_FORMAT_VERSION])?;
    writer.write_all(&(segments.len() as u32).to_le_bytes())?;
    for seg in segments {
        writer.write_all(&[seg.seg_type])?;
        writer.write_all(&(seg.payload.len() as u64).to_le_bytes())?;
        writer.write_all(&seg.payload)?;
    }
    Ok(())
}

/// Deserialise all segments from an RVF stream.
///
/// Unknown segment types are preserved verbatim, allowing forward compatibility.
pub fn read_rvf<R: Read>(reader: &mut R) -> Result<Vec<RvfSegment>, RvfError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != RVF_MAGIC {
        return Err(RvfError::InvalidMagic);
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != RVF_FORMAT_VERSION {
        return Err(RvfError::UnsupportedVersion(version[0]));
    }

    let mut count_bytes = [0u8; 4];
    reader.read_exact(&mut count_bytes)?;
    let count = u32::from_le_bytes(count_bytes) as usize;

    let mut segments = Vec::with_capacity(count);
    for _ in 0..count {
        let mut type_byte = [0u8; 1];
        reader.read_exact(&mut type_byte)?;

        let mut len_bytes = [0u8; 8];
        reader.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes) as usize;

        if len > MAX_SEGMENT_PAYLOAD {
            return Err(RvfError::PayloadTooLarge(len));
        }

        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;

        segments.push(RvfSegment {
            seg_type: type_byte[0],
            payload,
        });
    }
    Ok(segments)
}

// ── Higher-level helpers ──────────────────────────────────────────────────────

/// Extract and deserialise the `FerroImageManifest` from a list of segments.
///
/// Returns `RvfError::ManifestMissing` if no `SEG_MANIFEST` segment is present.
pub fn parse_manifest(segments: &[RvfSegment]) -> Result<FerroImageManifest, RvfError> {
    segments
        .iter()
        .find(|s| s.seg_type == SEG_MANIFEST)
        .ok_or(RvfError::ManifestMissing)
        .and_then(|s| serde_json::from_slice(&s.payload).map_err(RvfError::Serialization))
}

/// Read and validate an RVF image from disk.
///
/// Validation includes the required manifest and layer segments, the manifest
/// layer size, and the OCI-compatible `sha256:` layer digest. This gives
/// callers a single fail-closed boundary before exposing an RVF layer to an
/// OCI/rootfs reader.
pub fn read_rvf_image(path: &Path) -> Result<RvfImage, RvfError> {
    let mut file = std::fs::File::open(path)?;
    let segments = read_rvf(&mut file)?;
    for required_type in [SEG_MANIFEST, SEG_LAYER] {
        if segments
            .iter()
            .filter(|segment| segment.seg_type == required_type)
            .count()
            > 1
        {
            return Err(RvfError::DuplicateSegment(required_type));
        }
    }
    let manifest = parse_manifest(&segments)?;
    let layer = segments
        .iter()
        .find(|segment| segment.seg_type == SEG_LAYER)
        .ok_or(RvfError::LayerMissing)?;

    let actual_size = layer.payload.len() as u64;
    if manifest.layer_size != actual_size {
        return Err(RvfError::LayerSizeMismatch {
            expected: manifest.layer_size,
            actual: actual_size,
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(&layer.payload);
    let actual_digest = format!("sha256:{:x}", hasher.finalize());
    if manifest.layer_digest != actual_digest {
        return Err(RvfError::LayerDigestMismatch {
            expected: manifest.layer_digest,
            actual: actual_digest,
        });
    }

    Ok(RvfImage { manifest, segments })
}

/// Extract the validated OCI layer blob from an RVF image atomically.
///
/// The output is the exact compressed layer bytes referenced by the manifest,
/// suitable for importing into an OCI image store. The destination is synced
/// before rename and its parent directory is synced afterwards.
pub fn extract_layer(path: &Path, output_path: &Path) -> Result<u64, RvfError> {
    let image = read_rvf_image(path)?;
    let layer = image
        .segments
        .iter()
        .find(|segment| segment.seg_type == SEG_LAYER)
        .ok_or(RvfError::LayerMissing)?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = output_path.with_extension("rvf-layer.tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&layer.payload)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, output_path)?;
    if let Some(parent) = output_path.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(layer.payload.len() as u64)
}

/// Return `true` if `path` starts with the RVF magic bytes.
///
/// Does not validate the rest of the file — just a quick header probe.
pub fn is_rvf_image(path: &Path) -> bool {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .map(|_| &magic == RVF_MAGIC)
        .unwrap_or(false)
}

/// Build an `.rvf` image from an already-completed OCI build result.
///
/// The function reads the layer blob from disk (via `layer_blob_path`), assembles
/// the segment list, and writes the output file atomically via an in-memory buffer.
pub fn build_rvf_image(params: &RvfBuildParams<'_>) -> Result<RvfBuildResult, RvfError> {
    let layer_path =
        crate::dockerfile_build::layer_blob_path(params.runtime_dir, params.layer_digest);
    let layer_bytes = std::fs::read(&layer_path)?;

    // Update layer_size now that we have the actual bytes.
    let mut manifest = params.manifest.clone();
    manifest.layer_size = layer_bytes.len() as u64;

    let manifest_json = serde_json::to_vec(&manifest)?;

    let mut segments = vec![
        RvfSegment {
            seg_type: SEG_MANIFEST,
            payload: manifest_json,
        },
        RvfSegment {
            seg_type: SEG_LAYER,
            payload: layer_bytes,
        },
    ];

    if let Some(model_path) = params.embed_model_path {
        let model_bytes = std::fs::read(model_path)?;
        segments.push(RvfSegment {
            seg_type: SEG_VEC,
            payload: model_bytes,
        });
    }

    let segment_count = segments.len();

    // Serialise to memory first so we can compute the digest before disk I/O.
    let mut buf = Vec::new();
    write_rvf(&mut buf, &segments)?;

    let file_digest = hex::encode(rvf_crypto::shake256_256(&buf));
    let file_size = buf.len() as u64;

    let temporary = params.output_path.with_extension("rvf.tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&buf)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, params.output_path)?;
    if let Some(parent) = params.output_path.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(RvfBuildResult {
        output_path: params.output_path.to_path_buf(),
        file_digest,
        file_size,
        segment_count,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_manifest() -> FerroImageManifest {
        FerroImageManifest {
            name: "testapp".to_string(),
            tag: "1.0".to_string(),
            entrypoint: vec!["/bin/sh".to_string()],
            cmd: vec!["-c".to_string(), "echo hi".to_string()],
            env: vec!["PATH=/usr/local/bin:/usr/bin:/bin".to_string()],
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            created_at: "1700000000".to_string(),
            format_version: 1,
            layer_digest: "sha256:deadbeef".to_string(),
            layer_size: 1024,
            overlay_model_type: None,
        }
    }

    #[test]
    fn round_trip_single_segment() {
        let segments = vec![RvfSegment {
            seg_type: SEG_MANIFEST,
            payload: b"hello".to_vec(),
        }];

        let mut buf = Vec::new();
        write_rvf(&mut buf, &segments).unwrap();

        let read_back = read_rvf(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].seg_type, SEG_MANIFEST);
        assert_eq!(read_back[0].payload, b"hello");
    }

    #[test]
    fn round_trip_multiple_segments() {
        let segments = vec![
            RvfSegment {
                seg_type: SEG_MANIFEST,
                payload: b"manifest".to_vec(),
            },
            RvfSegment {
                seg_type: SEG_LAYER,
                payload: vec![0u8, 1, 2, 3],
            },
            RvfSegment {
                seg_type: SEG_VEC,
                payload: vec![9u8; 32],
            },
        ];

        let mut buf = Vec::new();
        write_rvf(&mut buf, &segments).unwrap();

        let read_back = read_rvf(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(read_back.len(), 3);
        assert_eq!(read_back[1].seg_type, SEG_LAYER);
        assert_eq!(read_back[2].payload, vec![9u8; 32]);
    }

    #[test]
    fn writer_rejects_duplicate_or_oversized_segments() {
        let duplicate = vec![
            RvfSegment {
                seg_type: SEG_LAYER,
                payload: vec![1],
            },
            RvfSegment {
                seg_type: SEG_LAYER,
                payload: vec![2],
            },
        ];
        assert!(matches!(
            write_rvf(&mut Vec::new(), &duplicate),
            Err(RvfError::DuplicateSegment(SEG_LAYER))
        ));
        let oversized = vec![RvfSegment {
            seg_type: SEG_LAYER,
            payload: vec![0; MAX_SEGMENT_PAYLOAD + 1],
        }];
        assert!(matches!(
            write_rvf(&mut Vec::new(), &oversized),
            Err(RvfError::PayloadTooLarge(size)) if size == MAX_SEGMENT_PAYLOAD + 1
        ));
    }

    #[test]
    fn parse_manifest_succeeds() {
        let manifest = sample_manifest();
        let json = serde_json::to_vec(&manifest).unwrap();
        let segments = vec![RvfSegment {
            seg_type: SEG_MANIFEST,
            payload: json,
        }];
        let parsed = parse_manifest(&segments).unwrap();
        assert_eq!(parsed.name, "testapp");
        assert_eq!(parsed.tag, "1.0");
        assert_eq!(parsed.layer_digest, "sha256:deadbeef");
    }

    #[test]
    fn parse_manifest_missing_returns_error() {
        let segments = vec![RvfSegment {
            seg_type: SEG_LAYER,
            payload: b"data".to_vec(),
        }];
        assert!(matches!(
            parse_manifest(&segments),
            Err(RvfError::ManifestMissing)
        ));
    }

    #[test]
    fn read_rvf_invalid_magic_returns_error() {
        let garbage = b"NOTRVF1_stuff";
        assert!(matches!(
            read_rvf(&mut Cursor::new(garbage)),
            Err(RvfError::InvalidMagic)
        ));
    }

    #[test]
    fn read_rvf_unsupported_version_returns_error() {
        // Build a header with version = 99
        let mut buf = Vec::new();
        buf.extend_from_slice(RVF_MAGIC);
        buf.push(99u8); // unsupported version
        buf.extend_from_slice(&0u32.to_le_bytes()); // 0 segments
        assert!(matches!(
            read_rvf(&mut Cursor::new(&buf)),
            Err(RvfError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn is_rvf_image_detects_valid_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let segments: Vec<RvfSegment> = vec![];
        let mut buf = Vec::new();
        write_rvf(&mut buf, &segments).unwrap();
        std::fs::write(&path, &buf).unwrap();

        assert!(is_rvf_image(&path));
    }

    #[test]
    fn is_rvf_image_rejects_non_rvf() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::fs::write(&path, b"this is not rvf").unwrap();
        assert!(!is_rvf_image(&path));
    }

    #[test]
    fn build_rvf_image_creates_valid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("runtime");
        let blobs_dir = runtime_dir.join("images").join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();

        // Write a fake layer blob at the expected path.
        let digest = "sha256:cafe0123";
        let blob_name = digest.replace(':', "_");
        let layer_blob = blobs_dir.join(&blob_name);
        std::fs::write(&layer_blob, b"fake_layer_tarball").unwrap();

        let output_path = tmp.path().join("myapp-1.0.rvf");
        let manifest = FerroImageManifest {
            name: "myapp".to_string(),
            tag: "1.0".to_string(),
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            created_at: "0".to_string(),
            format_version: 1,
            layer_digest: digest.to_string(),
            layer_size: 0, // overwritten by build_rvf_image
            overlay_model_type: None,
        };

        let params = RvfBuildParams {
            manifest,
            layer_digest: digest,
            runtime_dir: &runtime_dir,
            embed_model_path: None,
            output_path: &output_path,
        };

        let result = build_rvf_image(&params).unwrap();

        assert!(output_path.exists());
        assert_eq!(result.segment_count, 2); // SEG_MANIFEST + SEG_LAYER
        assert!(!result.file_digest.is_empty());
        assert!(result.file_size > 0);

        // Verify the file round-trips cleanly.
        let bytes = std::fs::read(&output_path).unwrap();
        let segments = read_rvf(&mut Cursor::new(&bytes)).unwrap();
        assert_eq!(segments.len(), 2);

        let manifest_back = parse_manifest(&segments).unwrap();
        assert_eq!(manifest_back.name, "myapp");
        assert_eq!(manifest_back.layer_size, b"fake_layer_tarball".len() as u64);
    }

    #[test]
    fn build_rvf_image_embeds_vec_model() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("runtime");
        let blobs_dir = runtime_dir.join("images").join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();

        let digest = "sha256:aabbccdd";
        let blob_name = digest.replace(':', "_");
        std::fs::write(blobs_dir.join(&blob_name), b"layer").unwrap();

        let model_file = tmp.path().join("model.bin");
        std::fs::write(&model_file, vec![0xffu8; 64]).unwrap();

        let output_path = tmp.path().join("myapp.rvf");
        let manifest = FerroImageManifest {
            name: "myapp".to_string(),
            tag: "latest".to_string(),
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            created_at: "0".to_string(),
            format_version: 1,
            layer_digest: digest.to_string(),
            layer_size: 0,
            overlay_model_type: None,
        };

        let params = RvfBuildParams {
            manifest,
            layer_digest: digest,
            runtime_dir: &runtime_dir,
            embed_model_path: Some(model_file.as_path()),
            output_path: &output_path,
        };

        let result = build_rvf_image(&params).unwrap();
        assert_eq!(result.segment_count, 3); // MANIFEST + LAYER + VEC

        let bytes = std::fs::read(&output_path).unwrap();
        let segments = read_rvf(&mut Cursor::new(&bytes)).unwrap();
        let vec_seg = segments.iter().find(|s| s.seg_type == SEG_VEC).unwrap();
        assert_eq!(vec_seg.payload, vec![0xffu8; 64]);
    }

    #[test]
    fn read_rvf_image_validates_layer_size_and_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = b"validated-layer";
        let mut hasher = Sha256::new();
        hasher.update(layer);
        let digest = format!("sha256:{:x}", hasher.finalize());
        let manifest = FerroImageManifest {
            name: "app".into(),
            tag: "latest".into(),
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            arch: "x86_64".into(),
            os: "linux".into(),
            created_at: "0".into(),
            format_version: RVF_FORMAT_VERSION,
            layer_digest: digest,
            layer_size: layer.len() as u64,
            overlay_model_type: None,
        };
        let image_path = tmp.path().join("image.rvf");
        let mut bytes = Vec::new();
        write_rvf(
            &mut bytes,
            &[
                RvfSegment {
                    seg_type: SEG_MANIFEST,
                    payload: serde_json::to_vec(&manifest).unwrap(),
                },
                RvfSegment {
                    seg_type: SEG_LAYER,
                    payload: layer.to_vec(),
                },
            ],
        )
        .unwrap();
        std::fs::write(&image_path, bytes).unwrap();

        let image = read_rvf_image(&image_path).unwrap();
        assert_eq!(image.manifest.name, "app");
        assert_eq!(image.segments.len(), 2);

        let output = tmp.path().join("oci-layer.tar");
        assert_eq!(
            extract_layer(&image_path, &output).unwrap(),
            layer.len() as u64
        );
        assert_eq!(std::fs::read(output).unwrap(), layer);
    }

    #[test]
    fn read_rvf_image_rejects_tampered_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = sample_manifest();
        let image_path = tmp.path().join("tampered.rvf");
        let mut bytes = Vec::new();
        write_rvf(
            &mut bytes,
            &[
                RvfSegment {
                    seg_type: SEG_MANIFEST,
                    payload: serde_json::to_vec(&manifest).unwrap(),
                },
                RvfSegment {
                    seg_type: SEG_LAYER,
                    payload: b"different".to_vec(),
                },
            ],
        )
        .unwrap();
        std::fs::write(&image_path, bytes).unwrap();

        assert!(matches!(
            read_rvf_image(&image_path),
            Err(RvfError::LayerSizeMismatch { .. }) | Err(RvfError::LayerDigestMismatch { .. })
        ));
    }
}
