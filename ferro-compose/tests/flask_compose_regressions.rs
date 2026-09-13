use ferro_compose::service_graph::ServiceGraph;
use ferro_compose::ComposeFile;
use std::collections::HashMap;

#[test]
fn flask_build_target_survives_compose_roundtrip() {
    let config = ComposeFile::parse(
        "services:\n  assets:\n    build:\n      context: .\n      target: assets\n",
        &HashMap::new(),
    )
    .unwrap();
    let serialized = serde_yaml::to_value(&config).unwrap();
    assert_eq!(
        serialized["services"]["assets"]["build"]["target"].as_str(),
        Some("assets")
    );
}

#[test]
fn flask_optional_missing_dependency_does_not_block_graph() {
    let config = ComposeFile::parse(
        "services:\n  web:\n    image: busybox\n    depends_on:\n      database:\n        condition: service_started\n        required: false\n",
        &HashMap::new(),
    ).expect("an unavailable optional dependency must not prevent web startup");
    assert_eq!(
        ServiceGraph::from_compose(&config).unwrap().start_batches(),
        vec![vec!["web"]]
    );
}

#[test]
fn flask_optional_dependency_flag_survives_compose_roundtrip() {
    let config = ComposeFile::parse(
        "services:\n  database:\n    image: postgres\n  web:\n    image: busybox\n    depends_on:\n      database:\n        condition: service_started\n        required: false\n",
        &HashMap::new(),
    ).unwrap();
    let serialized = serde_yaml::to_value(&config).unwrap();
    assert_eq!(
        serialized["services"]["web"]["depends_on"]["database"]["required"].as_bool(),
        Some(false)
    );
}

#[test]
fn flask_missing_dependency_is_required_by_default() {
    assert!(ComposeFile::parse(
        "services:\n  web:\n    image: busybox\n    depends_on:\n      database:\n        condition: service_started\n",
        &HashMap::new(),
    ).is_err());
}

#[test]
fn real_app_networks_are_project_owned_for_rootless_compose() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/real-app/compose.yml");
    let config = ComposeFile::parse(
        &std::fs::read_to_string(fixture).expect("read real-app Compose fixture"),
        &HashMap::new(),
    )
    .expect("parse real-app Compose fixture");
    let networks = config.networks.expect("real-app networks");
    assert_eq!(
        networks.len(),
        1,
        "real-app uses one rootless network lease"
    );
    assert!(!networks["app"].external, "app must be project-owned");
}
