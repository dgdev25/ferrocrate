fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../ferro-core/proto/buildkit";
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(
            config,
            &[
                format!(
                    "{proto_root}/github.com/moby/buildkit/api/services/control/control.proto"
                ),
                format!("{proto_root}/github.com/moby/buildkit/util/apicaps/pb/caps.proto"),
            ],
            &[proto_root.to_string()],
        )?;
    println!("cargo:rerun-if-changed={proto_root}");
    Ok(())
}
