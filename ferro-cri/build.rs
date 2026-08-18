fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_with_config(config, &["proto/runtime/v1/api.proto"], &["proto"])?;
    Ok(())
}
