pub mod admin;
pub mod agent;
pub mod config;
pub mod control;
pub mod controller_authorization;
pub mod desired_state;
pub mod enrollment;
pub mod limits;
pub mod metrics;
pub mod pki;
pub mod recovery;
pub mod revocation;
pub mod rotation;
pub mod rpc;
pub mod store;

pub mod proto {
    tonic::include_proto!("ferro.manager.v1");
}
