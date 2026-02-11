use crate::image_manifest::{ImageManifest, OCI_IMAGE_MANIFEST_MEDIA_TYPE, parse_image_manifest};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub reference: String,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid image reference: {0}")]
    InvalidReference(String),
    #[error("failed to build HTTP client: {0}")]
    ClientBuild(#[from] reqwest::Error),
    #[error("registry request failed: {0}")]
    Request(#[source] reqwest::Error),
    #[error("registry returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("manifest parse error: {0}")]
    ManifestParse(#[from] crate::image_manifest::ImageManifestParseError),
}

pub struct RegistryClient {
    client: Client,
}

impl RegistryClient {
    pub fn new() -> Result<Self, RegistryError> {
        let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
        Ok(Self { client })
    }

    /// Pull and parse OCI image manifest from registry using optional basic auth.
    pub fn pull_manifest(
        &self,
        image: &str,
        auth: Option<&RegistryAuth>,
    ) -> Result<ImageManifest, RegistryError> {
        let manifest = self.pull_manifest_raw(image, auth)?;
        Ok(parse_image_manifest(&manifest)?)
    }

    /// Pull raw manifest JSON for an image reference from OCI registry API.
    pub fn pull_manifest_raw(
        &self,
        image: &str,
        auth: Option<&RegistryAuth>,
    ) -> Result<String, RegistryError> {
        let image_ref = parse_image_reference(image)?;
        let url = manifest_url(&image_ref);

        let mut request = self
            .client
            .get(url)
            .header(ACCEPT, OCI_IMAGE_MANIFEST_MEDIA_TYPE);

        if let Some(auth) = auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }

        let response = request.send().map_err(RegistryError::Request)?;
        let status = response.status();
        let body = response.text().map_err(RegistryError::Request)?;

        if !status.is_success() {
            return Err(RegistryError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        Ok(body)
    }

    /// Push manifest JSON to an OCI registry using optional basic auth.
    pub fn push_manifest(
        &self,
        image: &str,
        manifest: &ImageManifest,
        auth: Option<&RegistryAuth>,
    ) -> Result<(), RegistryError> {
        let payload = serde_json::to_string(manifest).map_err(|err| {
            RegistryError::InvalidReference(format!("failed to serialize manifest: {err}"))
        })?;
        self.push_manifest_raw(image, &payload, auth)
    }

    /// Push raw manifest JSON to an OCI registry using optional basic auth.
    pub fn push_manifest_raw(
        &self,
        image: &str,
        manifest_json: &str,
        auth: Option<&RegistryAuth>,
    ) -> Result<(), RegistryError> {
        parse_image_manifest(manifest_json)?;
        let image_ref = parse_image_reference(image)?;
        let url = manifest_url(&image_ref);

        let mut request = self
            .client
            .put(url)
            .header(CONTENT_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE)
            .body(manifest_json.to_string());

        if let Some(auth) = auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }

        let response = request.send().map_err(RegistryError::Request)?;
        let status = response.status();
        let body = response.text().map_err(RegistryError::Request)?;
        if !status.is_success() {
            return Err(RegistryError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        Ok(())
    }
}

pub fn parse_image_reference(input: &str) -> Result<ImageReference, RegistryError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(RegistryError::InvalidReference(
            "image reference is empty".to_string(),
        ));
    }

    let (name_part, reference) = split_reference(raw);
    let parts: Vec<&str> = name_part.split('/').collect();

    if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
        return Err(RegistryError::InvalidReference(raw.to_string()));
    }

    let (registry, repository) = if is_registry_component(parts[0]) {
        if parts.len() < 2 {
            return Err(RegistryError::InvalidReference(raw.to_string()));
        }
        (parts[0].to_string(), parts[1..].join("/"))
    } else if parts.len() == 1 {
        (
            "registry-1.docker.io".to_string(),
            format!("library/{}", parts[0]),
        )
    } else {
        ("registry-1.docker.io".to_string(), parts.join("/"))
    };

    Ok(ImageReference {
        registry,
        repository,
        reference,
    })
}

fn split_reference(input: &str) -> (String, String) {
    let slash_idx = input.rfind('/');
    let colon_idx = input.rfind(':');

    if let Some(colon) = colon_idx {
        if slash_idx.is_none_or(|slash| colon > slash) {
            return (input[..colon].to_string(), input[colon + 1..].to_string());
        }
    }

    (input.to_string(), "latest".to_string())
}

fn is_registry_component(component: &str) -> bool {
    component.contains('.') || component.contains(':') || component == "localhost"
}

fn manifest_url(image_ref: &ImageReference) -> String {
    let scheme = if image_ref.registry.starts_with("localhost")
        || image_ref.registry.starts_with("127.")
        || image_ref.registry.contains(":")
    {
        "http"
    } else {
        "https"
    };

    format!(
        "{scheme}://{}/v2/{}/manifests/{}",
        image_ref.registry, image_ref.repository, image_ref.reference
    )
}

#[cfg(test)]
mod tests {
    use super::{RegistryAuth, RegistryClient, parse_image_reference};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use httptest::matchers::{all_of, contains, request};
    use httptest::responders::status_code;
    use httptest::{Expectation, Server};

    #[test]
    fn parses_image_reference_with_default_registry_and_latest_tag() {
        let parsed = parse_image_reference("alpine").expect("should parse");
        assert_eq!(parsed.registry, "registry-1.docker.io");
        assert_eq!(parsed.repository, "library/alpine");
        assert_eq!(parsed.reference, "latest");
    }

    #[test]
    fn parses_image_reference_with_custom_registry_and_tag() {
        let parsed = parse_image_reference("ghcr.io/acme/app:v1.2.3").expect("should parse");
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.repository, "acme/app");
        assert_eq!(parsed.reference, "v1.2.3");
    }

    #[test]
    fn sends_basic_auth_when_provided() {
        let server = Server::run();
        let auth_value = format!("Basic {}", STANDARD.encode("user:pass"));

        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/v2/test/image/manifests/latest"),
                request::headers(contains(("authorization", auth_value.clone())))
            ])
            .respond_with(status_code(200).body(
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#,
            )),
        );

        let client = RegistryClient::new().expect("client");
        let image = format!("{}/test/image", server.addr());
        let auth = RegistryAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let manifest = client
            .pull_manifest(&image, Some(&auth))
            .expect("manifest should be pulled");
        assert_eq!(manifest.schema_version, 2);
    }

    #[test]
    fn pushes_manifest_with_basic_auth() {
        let server = Server::run();
        let auth_value = format!("Basic {}", STANDARD.encode("writer:secret"));
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 1
            },
            "layers": []
        });

        server.expect(
            Expectation::matching(all_of![
                request::method_path("PUT", "/v2/test/image/manifests/latest"),
                request::headers(contains(("authorization", auth_value.clone()))),
                request::headers(contains(("content-type", "application/vnd.oci.image.manifest.v1+json")))
            ])
            .respond_with(status_code(201)),
        );

        let client = RegistryClient::new().expect("client");
        let image = format!("{}/test/image", server.addr());
        let auth = RegistryAuth {
            username: "writer".to_string(),
            password: "secret".to_string(),
        };

        client
            .push_manifest_raw(&image, &manifest_json.to_string(), Some(&auth))
            .expect("manifest push should succeed");
    }
}
