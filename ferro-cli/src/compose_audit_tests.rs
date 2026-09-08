use super::super::*;

fn project(value: serde_json::Value) -> ComposeProject {
    ComposeProject { path: PathBuf::from("/tmp/project/compose.yml"), compose: serde_json::from_value(value).unwrap() }
}

#[test]
fn explicit_profile_target_activates_dependencies_without_sibling_services() {
    let project = project(serde_json::json!({"services": {
        "web": {"image":"scratch", "profiles":["debug"], "depends_on":["db"]},
        "db": {"image":"scratch", "profiles":["debug"]},
        "unrelated": {"image":"scratch", "profiles":["debug"]}
    }}));
    let enabled = build_compose_enabled_set(&project, &[], &["web".into()]).unwrap();
    assert!(enabled.contains("web") && enabled.contains("db"));
    assert!(!enabled.contains("unrelated"));
}

#[test]
fn optional_missing_dependency_is_not_selected_or_required_by_profiles() {
    let project = project(serde_json::json!({"services": {
        "web": {"image":"scratch", "depends_on":{"missing":{"condition":"service_healthy", "required":false}}}
    }}));
    assert_eq!(compose_service_selection(&project, &["web".into()]).unwrap(), HashSet::from(["web".into()]));
    assert!(build_compose_enabled_set(&project, &[], &[]).unwrap().contains("web"));
}

#[test]
fn compose_ownership_never_matches_prefix_other_project_or_unlabelled_records() {
    let record = |project: &str, service: &str| -> ferro_core::container_store::ContainerRecord {
        serde_json::from_value(serde_json::json!({
            "id":"test", "name":"db-admin", "pid":0, "image":"scratch", "command":[],
            "created_at_unix":0, "stdout_path":"", "stderr_path":"", "status":"exited",
            "labels":{"com.docker.compose.project":project,"com.docker.compose.service":service}
        })).unwrap()
    };
    assert!(!compose_record_owned(&record("a","db-admin"), "a", "db"));
    assert!(!compose_record_owned(&record("b","db"), "a", "db"));
    assert!(!compose_record_owned(&record("",""), "a", "db"));
    assert!(compose_record_owned(&record("a","db"), "a", "db"));
}

#[test]
fn external_volume_uses_declared_name_and_is_not_project_prefixed() {
    let project = project(serde_json::json!({"name":"app", "services":{}, "volumes":{
        "shared":{"external":true}, "alias":{"external":true,"name":"existing"}, "owned":{}
    }}));
    for (source, expected) in [("shared","shared"),("alias","existing"),("owned","app_owned")] {
        assert_eq!(compose_project_volume_spec(Path::new("/tmp/app"), &project.compose, source).unwrap().0, expected);
    }
}

#[test]
fn filesync_rejects_staged_symlink_parents_without_outside_mutation() {
    let staging = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), staging.path().join("linked")).unwrap();
    for directory in [false, true] {
        assert!(buildkit_context_target(staging.path(), Path::new("linked/child"), directory).is_err());
    }
    assert!(!outside.path().join("child").exists());
    assert!(buildkit_context_target(staging.path(), Path::new("../child"), false).is_err());
    let path = buildkit_context_target(staging.path(), Path::new("safe/nested/file"), false).unwrap();
    assert!(path.parent().unwrap().is_dir());
}

#[test]
fn declared_body_length_does_not_allocate_until_bytes_arrive() {
    let mut body = Vec::new();
    assert!(read_http_body_bytes(&mut std::io::empty(), &mut body, 1024 * 1024 * 1024).is_err());
    assert_eq!(body.capacity(), 0);
}

#[test]
fn shared_named_volume_is_planned_once_across_services_and_replicas() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    let project = project(serde_json::json!({"name":"app", "services": {
        "one":{"build":".", "volumes":["shared:/data"]},
        "two":{"build":".", "volumes":["shared:/data"]}
    }, "volumes":{"shared":{}}}));
    let images = LocalImageStore::open(root.path().join("images")).unwrap();
    let volumes = LocalVolumeStore::open(root.path().join("volumes")).unwrap();
    let authorization = super::test_surface_authorization(root.path());
    let origin = RequestOrigin::cli_current().unwrap();
    let mut planned = HashSet::new();
    let mut creates = 0;
    for (name, instance) in [("one","one"),("two","two-1"),("two","two-2")] {
        let result = prepare_compose_service(&images, &volumes, &origin, &authorization,
            root.path(), &project.compose, name.into(), instance.into(),
            &project.compose.services[name], &mut planned).unwrap();
        creates += result.prerequisites.iter().filter(|step| matches!(step, ComposePrerequisite::VolumeCreate(_))).count();
    }
    assert_eq!(creates, 1);
}
