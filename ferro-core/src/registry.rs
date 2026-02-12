use crate::image_manifest::{ImageManifest, OCI_IMAGE_MANIFEST_MEDIA_TYPE, parse_image_manifest};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE, HeaderValue};
use reqwest::Method;
use std::time::Duration;
use std::path::Path;
use std::fs::File;
use std::io::{copy, Read};
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
    pub separator: ReferenceSeparator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSeparator {
    Tag,
    Digest,
}

impl ImageReference {
    pub fn canonical(&self) -> String {
        match self.separator {
            ReferenceSeparator::Tag => {
                format!("{}/{}:{}", self.registry, self.repository, self.reference)
            }
            ReferenceSeparator::Digest => {
                format!("{}/{}@{}", self.registry, self.repository, self.reference)
            }
        }
    }
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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
        if std::env::var("FERROCRATE_DEBUG_REGISTRY").is_ok() {
            eprintln!("registry: GET {}", url);
        }
        let accept = [
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            crate::image_manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
            crate::image_manifest::DOCKER_MANIFEST_MEDIA_TYPE,
            crate::image_manifest::DOCKER_MANIFEST_LIST_MEDIA_TYPE,
        ]
        .join(", ");
        let header_value = HeaderValue::from_str(&accept)
            .map_err(|err| RegistryError::InvalidReference(format!("accept header: {err}")))?;
        let headers = vec![(ACCEPT, header_value.clone())];
        let response = self.send_request_with_auth(
            Method::GET,
            &url,
            headers,
            None,
            auth,
        )?;
        let status = response.status();
        let body = response.text().map_err(RegistryError::Request)?;

        if status.as_u16() == 404 {
            if let Some(challenge) = self.ping_bearer_challenge(&image_ref, auth)? {
                let token = self.fetch_bearer_token(&challenge, auth)?;
                let retry = self
                    .build_request(&Method::GET, &url, &[(ACCEPT, header_value)], None, None, Some(&token))
                    .send()
                    .map_err(RegistryError::Request)?;
                let retry_status = retry.status();
                let retry_body = retry.text().map_err(RegistryError::Request)?;
                if retry_status.is_success() {
                    return Ok(retry_body);
                }
                return Err(RegistryError::HttpStatus {
                    status: retry_status.as_u16(),
                    body: retry_body,
                });
            }
        }

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
        self.push_manifest_raw_with_media_type(
            image,
            manifest_json,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            auth,
        )
    }

    pub fn push_manifest_raw_with_media_type(
        &self,
        image: &str,
        manifest_json: &str,
        media_type: &str,
        auth: Option<&RegistryAuth>,
    ) -> Result<(), RegistryError> {
        parse_image_manifest(manifest_json)?;
        let image_ref = parse_image_reference(image)?;
        let url = manifest_url(&image_ref);
        let content_type = HeaderValue::from_str(media_type).map_err(|err| {
            RegistryError::InvalidReference(format!("content-type: {err}"))
        })?;
        let response = self.send_request_with_auth(
            Method::PUT,
            &url,
            vec![(CONTENT_TYPE, content_type)],
            Some(manifest_json.as_bytes().to_vec()),
            auth,
        )?;
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

    /// Pull a blob (layer/config) by digest and write to a file.
    pub fn pull_blob_to_file(
        &self,
        image: &str,
        digest: &str,
        auth: Option<&RegistryAuth>,
        dest: &Path,
    ) -> Result<(), RegistryError> {
        let image_ref = parse_image_reference(image)?;
        let url = blob_url(&image_ref, digest);
        let mut response = self.send_request_with_auth(Method::GET, &url, Vec::new(), None, auth)?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(RegistryError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(RegistryError::Io)?;
        }
        let tmp_path = dest.with_extension(format!(
            "tmp-{}",
            std::process::id()
        ));
        let mut file = File::create(&tmp_path).map_err(RegistryError::Io)?;
        copy(&mut response, &mut file).map_err(RegistryError::Io)?;
        file.sync_all().map_err(RegistryError::Io)?;
        std::fs::rename(&tmp_path, dest).map_err(RegistryError::Io)?;
        Ok(())
    }

    /// Push a blob using the monolithic upload flow.
    pub fn push_blob_from_file(
        &self,
        image: &str,
        digest: &str,
        path: &Path,
        auth: Option<&RegistryAuth>,
    ) -> Result<(), RegistryError> {
        let image_ref = parse_image_reference(image)?;
        let base = upload_url(&image_ref);
        let response = self.send_request_with_auth(Method::POST, &base, Vec::new(), None, auth)?;
        let status = response.status();
        if !status.is_success() && status.as_u16() != 202 {
            let body = response.text().unwrap_or_default();
            return Err(RegistryError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|val| val.to_str().ok())
            .ok_or_else(|| RegistryError::InvalidReference("missing upload location".to_string()))?;

        let upload_url = normalize_location(location, &image_ref);
        let upload_url = format!("{upload_url}?digest={digest}");

        let mut file = File::open(path).map_err(RegistryError::Io)?;
        let mut body = Vec::new();
        file.read_to_end(&mut body).map_err(RegistryError::Io)?;

        let response = self.send_request_with_auth(
            Method::PUT,
            &upload_url,
            Vec::new(),
            Some(body),
            auth,
        )?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(RegistryError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

impl RegistryClient {
    fn ping_bearer_challenge(
        &self,
        image_ref: &ImageReference,
        auth: Option<&RegistryAuth>,
    ) -> Result<Option<BearerChallenge>, RegistryError> {
        let url = ping_url(image_ref);
        let response = self
            .build_request(&Method::GET, &url, &[], None, auth, None)
            .send()
            .map_err(RegistryError::Request)?;
        if response.status().as_u16() != 401 {
            return Ok(None);
        }
        Ok(response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bearer_challenge))
    }

    fn send_request_with_auth(
        &self,
        method: Method,
        url: &str,
        headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
        body: Option<Vec<u8>>,
        auth: Option<&RegistryAuth>,
    ) -> Result<reqwest::blocking::Response, RegistryError> {
        let mut response = self
            .build_request(&method, url, &headers, body.as_ref(), auth, None)
            .send()
            .map_err(RegistryError::Request)?;

        if response.status().as_u16() == 401 {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_bearer_challenge);
            if let Some(challenge) = challenge {
                let token = self.fetch_bearer_token(&challenge, auth)?;
                response = self
                    .build_request(&method, url, &headers, body.as_ref(), None, Some(&token))
                    .send()
                    .map_err(RegistryError::Request)?;
            }
        }
        Ok(response)
    }

    fn build_request(
        &self,
        method: &Method,
        url: &str,
        headers: &[(reqwest::header::HeaderName, reqwest::header::HeaderValue)],
        body: Option<&Vec<u8>>,
        auth: Option<&RegistryAuth>,
        bearer: Option<&str>,
    ) -> reqwest::blocking::RequestBuilder {
        let mut request = self.client.request(method.clone(), url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(auth) = auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }
        if let Some(token) = bearer {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.body(body.clone());
        }
        request
    }

    fn fetch_bearer_token(
        &self,
        challenge: &BearerChallenge,
        auth: Option<&RegistryAuth>,
    ) -> Result<String, RegistryError> {
        let mut request = self.client.get(&challenge.realm);
        if let Some(service) = challenge.service.as_ref() {
            request = request.query(&[("service", service)]);
        }
        if let Some(scope) = challenge.scope.as_ref() {
            request = request.query(&[("scope", scope)]);
        }
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

        let parsed = serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|err| RegistryError::InvalidReference(format!("token parse error: {err}")))?;
        let token = parsed
            .get("token")
            .or_else(|| parsed.get("access_token"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| RegistryError::InvalidReference("token missing".to_string()))?;
        Ok(token.to_string())
    }
}

fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let trimmed = header.trim();
    if !trimmed.to_ascii_lowercase().starts_with("bearer ") {
        return None;
    }
    let params = trimmed[7..].split(',').map(|part| part.trim());
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for param in params {
        let mut parts = param.splitn(2, '=');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim().trim_matches('"');
        match key {
            "realm" => realm = Some(value.to_string()),
            "service" => service = Some(value.to_string()),
            "scope" => scope = Some(value.to_string()),
            _ => {}
        }
    }
    realm.map(|realm| BearerChallenge { realm, service, scope })
}

pub fn parse_image_reference(input: &str) -> Result<ImageReference, RegistryError> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(RegistryError::InvalidReference(
            "image reference is empty".to_string(),
        ));
    }

    let (name_part, reference, separator) = split_reference(raw);
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
        separator,
    })
}

fn split_reference(input: &str) -> (String, String, ReferenceSeparator) {
    if let Some(at) = input.rfind('@') {
        return (
            input[..at].to_string(),
            input[at + 1..].to_string(),
            ReferenceSeparator::Digest,
        );
    }
    let slash_idx = input.rfind('/');
    let colon_idx = input.rfind(':');

    if let Some(colon) = colon_idx {
        if slash_idx.is_none_or(|slash| colon > slash) {
            return (
                input[..colon].to_string(),
                input[colon + 1..].to_string(),
                ReferenceSeparator::Tag,
            );
        }
    }

    (
        input.to_string(),
        "latest".to_string(),
        ReferenceSeparator::Tag,
    )
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

fn blob_url(image_ref: &ImageReference, digest: &str) -> String {
    let scheme = if image_ref.registry.starts_with("localhost")
        || image_ref.registry.starts_with("127.")
        || image_ref.registry.contains(":")
    {
        "http"
    } else {
        "https"
    };

    format!(
        "{scheme}://{}/v2/{}/blobs/{}",
        image_ref.registry, image_ref.repository, digest
    )
}

fn upload_url(image_ref: &ImageReference) -> String {
    let scheme = if image_ref.registry.starts_with("localhost")
        || image_ref.registry.starts_with("127.")
        || image_ref.registry.contains(":")
    {
        "http"
    } else {
        "https"
    };

    format!(
        "{scheme}://{}/v2/{}/blobs/uploads/",
        image_ref.registry, image_ref.repository
    )
}

fn ping_url(image_ref: &ImageReference) -> String {
    let scheme = if image_ref.registry.starts_with("localhost")
        || image_ref.registry.starts_with("127.")
        || image_ref.registry.contains(":")
    {
        "http"
    } else {
        "https"
    };

    format!("{scheme}://{}/v2/", image_ref.registry)
}

fn normalize_location(location: &str, image_ref: &ImageReference) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }

    let scheme = if image_ref.registry.starts_with("localhost")
        || image_ref.registry.starts_with("127.")
        || image_ref.registry.contains(":")
    {
        "http"
    } else {
        "https"
    };

    if location.starts_with('/') {
        format!("{scheme}://{}{}", image_ref.registry, location)
    } else {
        format!("{scheme}://{}/{}", image_ref.registry, location)
    }
}

#[cfg(test)]
mod tests {
    use super::{ReferenceSeparator, RegistryAuth, RegistryClient, parse_image_reference};
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
        assert_eq!(parsed.separator, ReferenceSeparator::Tag);
    }

    #[test]
    fn parses_image_reference_with_custom_registry_and_tag() {
        let parsed = parse_image_reference("ghcr.io/acme/app:v1.2.3").expect("should parse");
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.repository, "acme/app");
        assert_eq!(parsed.reference, "v1.2.3");
        assert_eq!(parsed.separator, ReferenceSeparator::Tag);
    }

    #[test]
    fn parses_image_reference_with_digest() {
        let parsed = parse_image_reference("registry-1.docker.io/library/alpine@sha256:deadbeef")
            .expect("should parse");
        assert_eq!(parsed.registry, "registry-1.docker.io");
        assert_eq!(parsed.repository, "library/alpine");
        assert_eq!(parsed.reference, "sha256:deadbeef");
        assert_eq!(parsed.separator, ReferenceSeparator::Digest);
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

    #[test]
    fn pulls_manifest_with_bearer_token() {
        let server = Server::run();
        let token = "token-123";
        let realm = format!("http://{}/token", server.addr());
        let challenge = format!(
            "Bearer realm=\"{realm}\",service=\"test\",scope=\"repository:test/image:pull\""
        );

        server.expect(
            Expectation::matching(request::method_path("GET", "/v2/test/image/manifests/latest"))
                .respond_with(status_code(401).append_header("WWW-Authenticate", challenge)),
        );

        server.expect(
            Expectation::matching(request::method_path("GET", "/token"))
                .respond_with(status_code(200).body(format!("{{\"token\":\"{token}\"}}"))),
        );

        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/v2/test/image/manifests/latest"),
                request::headers(contains(("authorization", format!("Bearer {token}"))))
            ])
            .respond_with(status_code(200).body(
                r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#,
            )),
        );

        let client = RegistryClient::new().expect("client");
        let image = format!("{}/test/image", server.addr());

        let manifest = client
            .pull_manifest(&image, None)
            .expect("manifest should be pulled");
        assert_eq!(manifest.schema_version, 2);
    }

    #[test]
    fn pushes_blob_via_monolithic_upload() {
        let server = Server::run();
        let upload_location = "/upload/123";
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        server.expect(
            Expectation::matching(request::method_path("POST", "/v2/myorg/app/blobs/uploads/"))
                .respond_with(
                    status_code(202).append_header("Location", upload_location),
                ),
        );

        server.expect(
            Expectation::matching(request::method_path("PUT", "/upload/123"))
                .respond_with(status_code(201)),
        );

        let client = RegistryClient::new().expect("create client");
        let image = format!("{}/myorg/app:v1", server.addr());

        let temp = tempfile::tempdir().expect("tempdir");
        let blob_path = temp.path().join("blob");
        std::fs::write(&blob_path, "BLOB").expect("write blob");

        client
            .push_blob_from_file(&image, digest, &blob_path, None)
            .expect("push blob");
    }
}
