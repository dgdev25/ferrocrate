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
