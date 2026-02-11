use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub const OCI_IMAGE_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
pub const OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
pub const DOCKER_MANIFEST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.v2+json";
pub const DOCKER_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";
pub const DOCKER_LAYER_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar";
pub const DOCKER_LAYER_GZIP_MEDIA_TYPE: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";

#[derive(Debug, Error)]
pub enum ImageManifestParseError {
    #[error("invalid OCI image manifest JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported manifest mediaType: {0}")]
    InvalidManifestMediaType(String),
    #[error("unsupported index mediaType: {0}")]
    InvalidIndexMediaType(String),
    #[error("unsupported config mediaType: {0}")]
    InvalidConfigMediaType(String),
    #[error("unsupported layer mediaType: {0}")]
    InvalidLayerMediaType(String),
}

/// Parse an OCI Image Spec v1.1 manifest document and validate core media types.
pub fn parse_image_manifest(json: &str) -> Result<ImageManifest, ImageManifestParseError> {
    let manifest: ImageManifest = serde_json::from_str(json)?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn parse_image_index(json: &str) -> Result<ImageIndex, ImageManifestParseError> {
    let index: ImageIndex = serde_json::from_str(json)?;
    index.validate()?;
    Ok(index)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    #[serde(default = "default_manifest_media_type")]
    pub media_type: String,
    pub config: Descriptor,
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    pub artifact_type: Option<String>,
    pub subject: Option<Descriptor>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

impl ImageManifest {
    pub fn validate(&self) -> Result<(), ImageManifestParseError> {
        if self.media_type != OCI_IMAGE_MANIFEST_MEDIA_TYPE
            && self.media_type != DOCKER_MANIFEST_MEDIA_TYPE
        {
            return Err(ImageManifestParseError::InvalidManifestMediaType(
                self.media_type.clone(),
            ));
        }

        if self.config.media_type != OCI_IMAGE_CONFIG_MEDIA_TYPE
            && self.config.media_type != DOCKER_IMAGE_CONFIG_MEDIA_TYPE
        {
            return Err(ImageManifestParseError::InvalidConfigMediaType(
                self.config.media_type.clone(),
            ));
        }

        for layer in &self.layers {
            let supported = layer.media_type == OCI_IMAGE_LAYER_MEDIA_TYPE
                || layer.media_type == OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE
                || layer.media_type == OCI_IMAGE_LAYER_ZSTD_MEDIA_TYPE
                || layer.media_type == DOCKER_LAYER_MEDIA_TYPE
                || layer.media_type == DOCKER_LAYER_GZIP_MEDIA_TYPE;

            if !supported {
                return Err(ImageManifestParseError::InvalidLayerMediaType(
                    layer.media_type.clone(),
                ));
            }
        }

        Ok(())
    }
}

fn default_manifest_media_type() -> String {
    OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string()
}

fn default_index_media_type() -> String {
    OCI_IMAGE_INDEX_MEDIA_TYPE.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    pub schema_version: u32,
    #[serde(default = "default_index_media_type")]
    pub media_type: String,
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

impl ImageIndex {
    pub fn validate(&self) -> Result<(), ImageManifestParseError> {
        if self.media_type != OCI_IMAGE_INDEX_MEDIA_TYPE
            && self.media_type != DOCKER_MANIFEST_LIST_MEDIA_TYPE
        {
            return Err(ImageManifestParseError::InvalidIndexMediaType(
                self.media_type.clone(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(default)]
    pub urls: Vec<String>,
    pub annotations: Option<HashMap<String, String>>,
    pub artifact_type: Option<String>,
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    pub os_version: Option<String>,
    #[serde(default)]
    pub os_features: Vec<String>,
    pub variant: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::parse_image_manifest;

    #[test]
    fn parses_valid_oci_image_manifest() {
        let manifest = r#"
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 7023
          },
          "layers": [
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "size": 32654
            },
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
              "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              "size": 14872
            }
          ]
        }
        "#;

        let parsed = parse_image_manifest(manifest).expect("manifest should parse");
        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.layers.len(), 2);
    }

    #[test]
    fn rejects_unknown_manifest_media_type() {
        let manifest = r#"
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.some.unknown.manifest",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 7023
          },
          "layers": []
        }
        "#;

        let err = parse_image_manifest(manifest).expect_err("should reject unknown media type");
        assert!(err
            .to_string()
            .contains("unsupported manifest mediaType"));
    }

    #[test]
    fn rejects_invalid_layer_media_type() {
        let manifest = r#"
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 7023
          },
          "layers": [
            {
              "mediaType": "application/vnd.some.unknown.layer",
              "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "size": 32654
            }
          ]
        }
        "#;

        let err = parse_image_manifest(manifest).expect_err("should reject unknown layer media type");
        assert!(err.to_string().contains("unsupported layer mediaType"));
    }
}
