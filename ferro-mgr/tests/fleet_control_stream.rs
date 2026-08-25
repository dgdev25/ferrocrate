#![cfg(target_os = "linux")]

use std::{sync::Arc, time::Duration};

use ferro_mgr::{
    fleet::{FleetCommand, FleetCommandResult},
    pki::{CertificateIdentity, CertificateRole},
    proto::{
        control_service_client::ControlServiceClient, control_service_server::ControlServiceServer,
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
            .add_service(ControlServiceServer::with_interceptor(
                server_service.as_ref().clone(),
                |mut request: tonic::Request<()>| {
                    request.extensions_mut().insert(CertificateIdentity {
                        cluster_id: "cluster-a".into(),
                        role: CertificateRole::Node {
                            node_id: "node-a".into(),
                        },
                        expires_at: i64::MAX,
                    });
                    Ok(request)
                },
            ))
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

#[tokio::test]
async fn control_stream_rejects_a_node_id_that_does_not_match_the_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    store
        .register_node(Enrollment {
            node_id: "node-a".into(),
            public_key: vec![1; 32],
            endpoint: "127.0.0.1:50053".into(),
        })
        .unwrap();
    let service = ControlServiceImpl::new("cluster-a", 1, vec![9; 32], store);
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ControlServiceServer::with_interceptor(
                service,
                |mut request: tonic::Request<()>| {
                    request.extensions_mut().insert(CertificateIdentity {
                        cluster_id: "cluster-a".into(),
                        role: CertificateRole::Node {
                            node_id: "node-b".into(),
                        },
                        expires_at: i64::MAX,
                    });
                    Ok(request)
                },
            ))
            .serve(address)
            .await
    });
    let mut client = loop {
        match ControlServiceClient::connect(format!("http://{address}")).await {
            Ok(client) => break client,
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    };
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let mut stream = client
        .control_stream(ReceiverStream::new(receiver))
        .await
        .unwrap()
        .into_inner();
    sender
        .send(AgentMessage {
            node_id: "node-a".into(),
            acknowledged_revision: 0,
            payload: Vec::new(),
        })
        .await
        .unwrap();
    let response = stream.message().await.unwrap().unwrap();
    assert_eq!(
        response.error,
        "node_id does not match certificate identity"
    );
    server.abort();
}
