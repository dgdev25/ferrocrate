use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args = env::args().skip(1).collect::<Vec<_>>();
    if raw_args.first().map(String::as_str) == Some("__ferrocrate_mapped_bwrap") {
        match ferro_core::runtime::run_mapped_bwrap_launcher(&raw_args[1..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("mapped bwrap launcher: {error}");
                std::process::exit(125);
            }
        }
    }
    if raw_args.first().map(String::as_str) == Some("__ferrocrate_rootfs_launch") {
        if let Err(err) = ferro_core::runtime::run_rootfs_launcher(&raw_args[1..]) {
            eprintln!("rootfs launcher: {err}");
            std::process::exit(125);
        }
        std::process::exit(125);
    }
    let socket = env::var("FERROCRATE_CRI_SOCKET")
        .unwrap_or_else(|_| "/run/ferrocrate/cri.sock".to_string());
    ferro_cri::server::serve(socket).await?;
    Ok(())
}
