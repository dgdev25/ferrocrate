fn main() {
    ferro_mgr::config::ManagerLimits::default().validate().expect("valid manager limits");
    tracing::info!("ferro-mgr protocol service configured");
}
