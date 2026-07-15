pub mod config;
pub mod control;
pub mod desired_state;
pub mod limits;
pub mod admin;
pub mod agent;
pub mod enrollment;
pub mod pki;
pub mod recovery;
pub mod store;

pub mod proto {
    tonic::include_proto!("ferro.manager.v1");
}
