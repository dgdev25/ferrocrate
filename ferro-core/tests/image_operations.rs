#![cfg(target_os = "linux")]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ferro_core::authorization::RequestOrigin;
use ferro_core::image_manifest::{parse_image_manifest, OCI_IMAGE_MANIFEST_MEDIA_TYPE};
use ferro_core::image_store::LocalImageStore;
use ferro_core::image_tagging::{
    execute_image_tag_authorized, prepare_image_tag, resolve_reference,
};
use ferro_core::registry::{RegistryAuth, RegistryClient};
use ferro_core::runtime::ContainerRuntime;
use httptest::matchers::{all_of, contains, request};
use httptest::responders::status_code;
use httptest::{Expectation, Server};
use sha2::Digest;

#[test]
fn fixture_manifest_and_index_match_oci_media_types() {
    let manifest = include_str!("../../tests/fixtures/oci/manifest.json");
    let parsed = parse_image_manifest(manifest).expect("OCI fixture manifest should validate");
    assert_eq!(parsed.layers.len(), 1);

    let index = include_str!("../../tests/fixtures/oci/index.json");
    let parsed = ferro_core::image_manifest::parse_image_index(index)
        .expect("OCI fixture index should validate");
    assert_eq!(parsed.manifests.len(), 2);
}

#[test]
fn malformed_oci_descriptors_fail_closed() {
    let manifest = r#"{
        "schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:not-a-digest","size":1},
        "layers":[]
    }"#;
    assert!(parse_image_manifest(manifest).is_err());

    let manifest = r#"{
        "schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":-1},
        "layers":[]
    }"#;
    assert!(parse_image_manifest(manifest).is_err());
}

#[test]
fn malformed_oci_platform_descriptors_fail_closed() {
    let index = r#"{
        "schemaVersion":2,
        "mediaType":"application/vnd.oci.image.index.v1+json",
        "manifests":[{
            "mediaType":"application/vnd.oci.image.manifest.v1+json",
            "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size":1,
            "platform":{"os":"","architecture":"amd64"}
        }]
    }"#;
    assert!(ferro_core::image_manifest::parse_image_index(index).is_err());
}

#[test]
fn integration_pull_store_and_tag_image() {
    let server = Server::run();
    let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#;

    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/alpine/manifests/latest",
        ))
        .respond_with(status_code(200).body(manifest_json)),
    );

    let client = RegistryClient::new().expect("create client");
    let image = format!("{}/library/alpine", server.addr());
    let manifest = client
        .pull_manifest(&image, None)
        .expect("pull manifest should succeed");

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
    let authorization = runtime.surface_authorization().expect("authorization");
    let origin = RequestOrigin::cli_current().expect("origin");
    let store = LocalImageStore::open(temp.path().join("images")).expect("open store");
    let write = store
        .prepare_reference_write(
            &format!("{}/library/alpine:latest", server.addr()),
            &manifest.config.digest,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            manifest_json,
        )
        .expect("prepare manifest index");
    let permit = authorization
        .authorize_image_reference_write_plan(&origin, &write)
        .expect("authorize write");
    store
        .put_reference_authorized(write, permit)
        .expect("store manifest index");

    let tag = prepare_image_tag(
        &store,
        &format!("{}/library/alpine:latest", server.addr()),
        "ghcr.io/acme/alpine:stable",
    )
    .expect("prepare tag");
    let permit = authorization
        .authorize_image_tag_plan(&origin, &tag)
        .expect("authorize tag");
    execute_image_tag_authorized(&store, tag, permit).expect("tag image");

    let tagged = resolve_reference(&store, "ghcr.io/acme/alpine:stable")
        .expect("resolve tagged")
        .expect("tagged image exists");

    assert_eq!(tagged.digest, manifest.config.digest);
}

#[test]
fn integration_push_manifest_with_basic_auth() {
    let server = Server::run();
    let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#;
    let auth = RegistryAuth {
        username: "writer".to_string(),
        password: "secret".to_string(),
    };
    let auth_value = format!("Basic {}", STANDARD.encode("writer:secret"));

    server.expect(
        Expectation::matching(all_of![
            request::method_path("PUT", "/v2/myorg/app/manifests/v1"),
            request::headers(contains(("authorization", auth_value))),
            request::headers(contains(("content-type", OCI_IMAGE_MANIFEST_MEDIA_TYPE)))
        ])
        .respond_with(status_code(201)),
    );

    let client = RegistryClient::new().expect("create client");
    let image = format!("{}/myorg/app:v1", server.addr());

    client
        .push_manifest_raw(&image, manifest_json, Some(&auth))
        .expect("push manifest should succeed");

    let parsed = parse_image_manifest(manifest_json).expect("manifest should remain valid");
    assert_eq!(parsed.schema_version, 2);
}

const CHILD_MANIFEST_AMD64: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13},"layers":[]}"#;
const CHILD_MANIFEST_ARM64: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":13},"layers":[]}"#;

fn manifest_list_json() -> String {
    let amd64_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(CHILD_MANIFEST_AMD64.as_bytes())
    );
    let arm64_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(CHILD_MANIFEST_ARM64.as_bytes())
    );
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": arm64_digest,
                "size": CHILD_MANIFEST_ARM64.len(),
                "platform": {"architecture": "arm64", "os": "linux"}
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": amd64_digest,
                "size": CHILD_MANIFEST_AMD64.len(),
                "platform": {"architecture": "amd64", "os": "linux"}
            }
        ]
    })
    .to_string()
}

#[test]
fn registry_corpus_resolves_platform_manifest_from_manifest_list() {
    let server = Server::run();
    let index = manifest_list_json();
    let expected_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(CHILD_MANIFEST_AMD64.as_bytes())
    );

    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/multiarch/manifests/latest",
        ))
        .respond_with(status_code(200).body(index)),
    );
    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            format!("/v2/library/multiarch/manifests/{expected_digest}"),
        ))
        .respond_with(status_code(200).body(CHILD_MANIFEST_AMD64)),
    );

    let image = format!("{}/library/multiarch:latest", server.addr());
    let binding = ferro_core::image_fetch::inspect_image_binding(&image)
        .expect("platform manifest should resolve");
    assert_eq!(binding.manifest_digest(), expected_digest);
    assert_eq!(
        binding.config_digest(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
}

#[test]
fn registry_corpus_rejects_registry_manifest_with_unknown_media_type() {
    let server = Server::run();
    let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.example.manifest.v9+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13},"layers":[]}"#;
    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/unknown-type/manifests/latest",
        ))
        .respond_with(status_code(200).body(manifest_json)),
    );

    let client = RegistryClient::new().expect("create client");
    let image = format!("{}/library/unknown-type:latest", server.addr());
    let error = client
        .pull_manifest(&image, None)
        .expect_err("unknown manifest media type must fail closed");
    assert!(
        error.to_string().contains("unsupported manifest mediaType"),
        "explicit media type error expected, got {error}"
    );
}

#[test]
fn registry_corpus_rejects_registry_layer_with_unknown_media_type() {
    let server = Server::run();
    let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13},"layers":[{"mediaType":"application/x-example.unknown.layer","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":16}]}"#;
    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/unknown-layer/manifests/latest",
        ))
        .respond_with(status_code(200).body(manifest_json)),
    );

    let client = RegistryClient::new().expect("create client");
    let image = format!("{}/library/unknown-layer:latest", server.addr());
    let error = client
        .pull_manifest(&image, None)
        .expect_err("unknown layer media type must fail closed");
    assert!(
        error.to_string().contains("unsupported layer mediaType"),
        "explicit layer media type error expected, got {error}"
    );
}

#[test]
fn registry_corpus_index_with_non_manifest_child_fails_closed() {
    let server = Server::run();
    let index = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":16}]}"#;
    server.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/bad-index/manifests/latest",
        ))
        .respond_with(status_code(200).body(index)),
    );

    let image = format!("{}/library/bad-index:latest", server.addr());
    let error = ferro_core::image_fetch::inspect_image_binding(&image)
        .expect_err("index with layer-typed child must fail closed");
    assert!(
        error.to_string().contains("unsupported manifest mediaType"),
        "explicit child descriptor error expected, got {error}"
    );
}

fn manifest_with_layer_media_type(media_type: &str) -> String {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13}},"layers":[{{"mediaType":"{media_type}","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":16}}]}}"#
    )
}

#[test]
fn media_type_corpus_accepts_documented_oci_and_docker_types() {
    for media_type in [
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    ] {
        parse_image_manifest(&manifest_with_layer_media_type(media_type)).unwrap_or_else(|error| {
            panic!("documented layer media type {media_type} rejected: {error}")
        });
    }

    let docker_manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13},"layers":[]}"#;
    parse_image_manifest(docker_manifest).expect("Docker schema2 manifest must be accepted");

    let index = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13}]}"#;
    ferro_core::image_manifest::parse_image_index(index).expect("OCI index must be accepted");

    let docker_list = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13}]}"#;
    ferro_core::image_manifest::parse_image_index(docker_list)
        .expect("Docker manifest list must be accepted");
}

#[test]
fn media_type_corpus_rejects_undocumented_types() {
    let error = parse_image_manifest(&manifest_with_layer_media_type(
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    ))
    .expect_err("deprecated nondistributable layer type must be rejected");
    assert!(error.to_string().contains("unsupported layer mediaType"));

    let error = parse_image_manifest(
        r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.example.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13},"layers":[]}"#,
    )
    .expect_err("unknown config media type must be rejected");
    assert!(error.to_string().contains("unsupported config mediaType"));

    let error = ferro_core::image_manifest::parse_image_index(
        r#"{"schemaVersion":2,"mediaType":"application/vnd.example.index.v1+json","manifests":[]}"#,
    )
    .expect_err("unknown index media type must be rejected");
    assert!(error.to_string().contains("unsupported index mediaType"));
}

#[test]
fn malformed_oci_descriptor_digest_shapes_fail_closed() {
    for digest in [
        // Unknown algorithm.
        "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Missing algorithm prefix.
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Wrong length for sha256.
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Uppercase hex is not canonical.
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{digest}","size":13}},"layers":[]}}"#
        );
        let error = parse_image_manifest(&manifest)
            .expect_err(format!("digest {digest} must be rejected").as_str());
        assert!(
            error.to_string().contains("invalid descriptor digest"),
            "explicit digest rejection expected for {digest}, got {error}"
        );
    }

    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":13},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":-2}]}"#;
    let error = parse_image_manifest(manifest).expect_err("negative layer size must be rejected");
    assert!(error.to_string().contains("invalid descriptor size"));
}
