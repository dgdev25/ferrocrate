#![cfg(target_os = "linux")]

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use ferro_mgr::fleet::{
    AuditJournal, BrowserIdentity, FleetRole, FleetUi, FleetUiBackend,
};
use ferro_web::StaticAssets;
use serde_json::{json, Value};

struct TestAssets;

impl StaticAssets for TestAssets {
    fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
        (path == "index.html").then(|| (b"<main>Fleet</main>".to_vec(), "text/html"))
    }
}

struct TestBackend;

impl FleetUiBackend for TestBackend {
    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>> {
        Box::pin(async { Ok(json!({"hosts":[{"node_id":"node-a"}]})) })
    }

    fn operate(
        &self,
        command: &str,
        _arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>> {
        let command = command.to_string();
        Box::pin(async move { Ok(json!({"command":command,"ok":true})) })
    }
}

#[tokio::test]
async fn view_role_reads_but_operate_is_forbidden_and_witnessed() {
    let directory = tempfile::tempdir().unwrap();
    let audit = Arc::new(AuditJournal::open(directory.path().join("audit.jsonl")).unwrap());
    let ui = FleetUi::new(
        Arc::new(TestAssets),
        Arc::new(TestBackend),
        audit.clone(),
        60,
    )
    .unwrap();
    let credential = ui
        .mint_login(
            BrowserIdentity {
                principal: "mtls:view-cert".into(),
                role: FleetRole::View,
            },
            60,
        )
        .unwrap();
    let server = ui
        .spawn_insecure_loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let login = client
        .post(format!("http://{}/fleet/login", server.addr()))
        .json(&json!({"credential":credential}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let login: Value = login.json().await.unwrap();
    let token = login["token"].as_str().unwrap();

    let snapshot = client
        .post(format!(
            "http://{}/__tauri/get_fleet_snapshot",
            server.addr()
        ))
        .bearer_auth(token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(snapshot.status(), 200);
    let denied = client
        .post(format!("http://{}/__tauri/fleet_command", server.addr()))
        .bearer_auth(token)
        .json(&json!({
            "node_id":"node-a",
            "action":"run_container",
            "arguments":{"name":"demo","image":"alpine","command":[]}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let entries = audit.read_all().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].principal, "mtls:view-cert");
    assert_eq!(format!("{:?}", entries[0].result), "Denied");
    server.shutdown().await;
}

#[tokio::test]
async fn expired_browser_session_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let ui = FleetUi::new(
        Arc::new(TestAssets),
        Arc::new(TestBackend),
        Arc::new(AuditJournal::open(directory.path().join("audit.jsonl")).unwrap()),
        1,
    )
    .unwrap();
    let credential = ui
        .mint_login(
            BrowserIdentity {
                principal: "mtls:operator-cert".into(),
                role: FleetRole::Operate,
            },
            60,
        )
        .unwrap();
    let server = ui
        .spawn_insecure_loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let login: Value = client
        .post(format!("http://{}/fleet/login", server.addr()))
        .json(&json!({"credential":credential}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let response = client
        .post(format!(
            "http://{}/__tauri/get_fleet_snapshot",
            server.addr()
        ))
        .bearer_auth(login["token"].as_str().unwrap())
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    server.shutdown().await;
}
