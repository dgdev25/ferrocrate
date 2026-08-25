#![cfg(target_os = "linux")]

use std::{sync::Arc, time::Duration};

use ferro_mgr::{
    fleet::{FleetCommand, FleetCommandResult},
    proto::{
        control_service_client::ControlServiceClient,
        control_service_server::ControlServiceServer,
        AgentMessage,
    },
    rpc::ControlServiceImpl,
    store::{Enrollment, ManagerStore},
};
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

#[tokio::test]
async fn control_stream_carries_inventory_commands_and_results() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    store
        .register_node(Enrollment {
            node_id: "node-a".into(),
            public_key: vec![1; 32],
            endpoint: "127.0.0.1:50053".into(),
        })
        .unwrap();
    let service = Arc::new(ControlServiceImpl::new(
        "cluster-a",
        1,
        vec![9; 32],
        store.clone(),
    ));
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let server_service = service.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ControlServiceServer::from_arc(server_service))
            .serve(address)
            .await
    });
    let mut client = loop {
        match ControlServiceClient::connect(format!("http://{address}")).await {
            Ok(client) => break client,
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    };
    let (agent_sender, agent_receiver) = tokio::sync::mpsc::channel(8);
    let mut manager_stream = client
        .control_stream(ReceiverStream::new(agent_receiver))
        .await
        .unwrap()
        .into_inner();
    agent_sender
        .send(AgentMessage {
            node_id: "node-a".into(),
            acknowledged_revision: 0,
            payload: serde_json::to_vec(&json!({
                "kind":"observation",
                "version":"0.1.0",
                "health":"healthy",
                "doctor_summary":"all checks passed",
                "containers":[{"id":"abc","name":"fleet-demo","status":"running"}],
                "observed_at":1000
            }))
            .unwrap(),
        })
        .await
        .unwrap();
    let desired = manager_stream.message().await.unwrap().unwrap();
    assert!(desired.desired_state.is_some());
    let hosts = store.list_hosts().unwrap();
    assert_eq!(hosts[0].last_seen_unix, Some(1_000));

    let hub = service.fleet_hub();
    let execute = tokio::spawn(async move {
        hub.execute(
            "node-a",
            "logs",
            json!({"container":"fleet-demo"}),
            Duration::from_secs(1),
        )
        .await
    });
    let manager_command = manager_stream.message().await.unwrap().unwrap();
    let command: FleetCommand = serde_json::from_slice(&manager_command.command_json).unwrap();
    agent_sender
        .send(AgentMessage {
            node_id: "node-a".into(),
            acknowledged_revision: 0,
            payload: serde_json::to_vec(&json!({
                "kind":"command_result",
                "request_id":command.request_id,
                "exit_code":0,
                "stdout":"fleet log line\n",
                "stderr":""
            }))
            .unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(
        execute.await.unwrap().unwrap(),
        FleetCommandResult {
            request_id: command.request_id,
            exit_code: 0,
            stdout: "fleet log line\n".into(),
            stderr: String::new(),
        }
    );
    server.abort();
}
