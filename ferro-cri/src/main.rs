use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = env::var("FERROCRATE_CRI_SOCKET")
        .unwrap_or_else(|_| "/run/ferrocrate/cri.sock".to_string());
    ferro_cri::server::serve(socket).await?;
    Ok(())
}
