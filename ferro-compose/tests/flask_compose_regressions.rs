use ferro_compose::{ComposeFile, ServiceGraph};
use std::collections::HashMap;

#[test]
fn flask_build_target_survives_compose_roundtrip() {
    let config = ComposeFile::parse(
        "services:\n  assets:\n    build:\n      context: .\n      target: assets\n",
        &HashMap::new(),
    ).unwrap();
    let serialized = serde_yaml::to_value(&config).unwrap();
    assert_eq!(serialized["services"]["assets"]["build"]["target"].as_str(), Some("assets"));
}

#[test]
fn flask_optional_missing_dependency_does_not_block_graph() {
    let config = ComposeFile::parse(
        "services:\n  web:\n    image: busybox\n    depends_on:\n      database:\n        condition: service_started\n        required: false\n",
        &HashMap::new(),
    ).expect("an unavailable optional dependency must not prevent web startup");
    assert_eq!(ServiceGraph::from_compose(&config).unwrap().start_batches(), vec![vec!["web"]]);
}

#[test]
fn flask_optional_dependency_flag_survives_compose_roundtrip() {
    let config = ComposeFile::parse(
        "services:\n  database:\n    image: postgres\n  web:\n    image: busybox\n    depends_on:\n      database:\n        condition: service_started\n        required: false\n",
        &HashMap::new(),
    ).unwrap();
    let serialized = serde_yaml::to_value(&config).unwrap();
    assert_eq!(serialized["services"]["web"]["depends_on"]["database"]["required"].as_bool(), Some(false));
}

#[test]
fn flask_missing_dependency_is_required_by_default() {
    assert!(ComposeFile::parse(
        "services:\n  web:\n    image: busybox\n    depends_on:\n      database:\n        condition: service_started\n",
        &HashMap::new(),
    ).is_err());
}
