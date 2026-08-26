#![cfg(target_os = "linux")]

use std::{sync::Arc, time::Duration};

use ferro_mgr::{
    fleet::{ControlHub, FleetCommandResult},
    store::{Enrollment, ManagerStore},
};
use serde_json::json;

fn hub() -> Arc<ControlHub> {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.keep().join("manager.sqlite");
    let store = Arc::new(ManagerStore::open(database).unwrap());
    store
        .register_node(Enrollment {
            node_id: "node-a".into(),
            public_key: vec![1; 32],
            endpoint: "127.0.0.1:50053".into(),
        })
        .unwrap();
    Arc::new(ControlHub::new(store))
}

#[tokio::test]
async fn command_round_trip_is_correlated_to_the_connected_host() {
    let hub = hub();
    let mut connection = hub.connect("node-a").unwrap();
    let executor = hub.clone();
    let task = tokio::spawn(async move {
        executor
            .execute(
                "node-a",
                "logs",
                json!({"container":"fleet-demo"}),
                Duration::from_secs(1),
            )
            .await
    });
    let command = connection.receiver.recv().await.unwrap();
    assert_eq!(command.action, "logs");
    assert_eq!(command.arguments["container"], "fleet-demo");
    hub.complete(
        "node-a",
        FleetCommandResult {
            request_id: command.request_id,
            exit_code: 0,
            stdout: "hello from node-a\n".into(),
            stderr: String::new(),
        },
    );
    assert_eq!(task.await.unwrap().unwrap().stdout, "hello from node-a\n");
}

#[tokio::test]
async fn disconnected_unknown_and_mismatched_results_fail_closed() {
    let hub = hub();
    assert!(hub
        .execute("node-a", "ps", json!({}), Duration::from_millis(10))
        .await
        .unwrap_err()
        .contains("not connected"));

    let mut connection = hub.connect("node-a").unwrap();
    assert!(hub.connect("node-a").is_err());
    let executor = hub.clone();
    let task = tokio::spawn(async move {
        executor
            .execute("node-a", "ps", json!({}), Duration::from_secs(1))
            .await
    });
    let command = connection.receiver.recv().await.unwrap();
    hub.complete(
        "node-b",
        FleetCommandResult {
            request_id: command.request_id,
            exit_code: 0,
            stdout: "wrong host".into(),
            stderr: String::new(),
        },
    );
    hub.complete(
        "node-a",
        FleetCommandResult {
            request_id: command.request_id,
            exit_code: 0,
            stdout: "right host".into(),
            stderr: String::new(),
        },
    );
    assert_eq!(task.await.unwrap().unwrap().stdout, "right host");
    drop(connection);
    assert!(!hub.is_connected("node-a"));
}
