pub mod config;
pub mod recovery;
pub mod store;

pub mod proto {
    tonic::include_proto!("ferro.manager.v1");
}
