use clap::{Parser, Subcommand};
use ferro_core::image_store::LocalImageStore;
use ferro_core::registry::parse_image_reference;
use ferro_core::runtime::ContainerRuntime;
use ferro_compose::compose::{
    ComposeProject, compose_down, compose_logs, compose_ps, compose_up, find_compose_file,
};
use std::process;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ferrocrate", version, about = "FerroCrate CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Run {
        image: String,
        #[arg(long, default_value = "ebpf")]
        network_backend: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Build {
        dockerfile: String,
        #[arg(short, long)]
        tag: Option<String>,
    },
    Images,
    Rmi {
        image: String,
    },
    ImagePrune,
    Containers,
    Logs {
        container: String,
    },
    Exec {
        container: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Pull {
        image: String,
    },
    Push {
        image: String,
    },
    Compose {
        #[arg(short, long)]
        file: Option<String>,
        #[command(subcommand)]
        command: ComposeCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ComposeCommands {
    Up,
    Down,
    Ps,
    Logs,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn dispatch(command: Commands) -> Result<(), String> {
    let runtime_dir = runtime_dir();
    let runtime = ContainerRuntime::new(&runtime_dir).map_err(|err| err.to_string())?;
    let image_store = LocalImageStore::open(runtime_dir.join("images"))
        .map_err(|err| err.to_string())?;

    match command {
        Commands::Run { image, cmd, network_backend } => {
            handle_run(&runtime, &image, &cmd, &network_backend)
        }
        Commands::Build { dockerfile, tag } => handle_build(&dockerfile, tag.as_deref()),
        Commands::Images => handle_images(&image_store),
        Commands::Rmi { image } => handle_rmi(&image_store, &image),
        Commands::ImagePrune => handle_image_prune(&image_store),
        Commands::Containers => handle_containers(&runtime),
        Commands::Logs { container } => handle_logs(&runtime, &container),
        Commands::Exec { container, cmd } => handle_exec(&runtime, &container, &cmd),
        Commands::Pull { image } => handle_pull(&image),
        Commands::Push { image } => handle_push(&image),
        Commands::Compose { file, command } => handle_compose(file.as_deref(), command),
    }
}

fn handle_run(
    runtime: &ContainerRuntime,
    image: &str,
    cmd: &[String],
    network_backend: &str,
) -> Result<(), String> {
    validate_network_backend(network_backend)?;
    let record = runtime
        .run(image, cmd)
        .map_err(|err| err.to_string())?;
    println!(
        "run: container_id={} pid={} network_backend={}",
        record.id, record.pid, network_backend
    );
    Ok(())
}

fn handle_build(dockerfile: &str, tag: Option<&str>) -> Result<(), String> {
    if dockerfile.trim().is_empty() {
        return Err("build: dockerfile path is required".to_string());
    }

    let tag_display = tag.unwrap_or("<none>");
    if let Some(tag) = tag {
        parse_image_reference(tag).map_err(|err| err.to_string())?;
    }

    println!("build: dockerfile={dockerfile} tag={tag_display}");
    Ok(())
}

fn validate_network_backend(value: &str) -> Result<(), String> {
    match value {
        "ebpf" | "iptables" | "nftables" => Ok(()),
        _ => Err("network-backend must be one of: ebpf, iptables, nftables".to_string()),
    }
}

fn handle_images(store: &LocalImageStore) -> Result<(), String> {
    let records = store.list_references().map_err(|err| err.to_string())?;
    if records.is_empty() {
        println!("images: no entries");
        return Ok(());
    }
    for record in records {
        println!("{} {}", record.reference, record.digest);
    }
    Ok(())
}

fn handle_rmi(store: &LocalImageStore, image: &str) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    let removed = store.remove_reference(image).map_err(|err| err.to_string())?;
    if removed {
        println!("rmi: removed {image}");
    } else {
        println!("rmi: not found {image}");
    }
    Ok(())
}

fn handle_image_prune(store: &LocalImageStore) -> Result<(), String> {
    let removed = store.prune_references().map_err(|err| err.to_string())?;
    println!("image prune: removed={removed}");
    Ok(())
}

fn handle_containers(runtime: &ContainerRuntime) -> Result<(), String> {
    let records = runtime.list().map_err(|err| err.to_string())?;
    if records.is_empty() {
        println!("containers: no entries");
        return Ok(());
    }
    for record in records {
        println!(
            "{} {} {}",
            record.id,
            record.image,
            record.status
        );
    }
    Ok(())
}

fn handle_logs(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("logs: container is required".to_string());
    }
    let logs = runtime.logs(container).map_err(|err| err.to_string())?;
    print!("{logs}");
    Ok(())
}

fn handle_exec(runtime: &ContainerRuntime, container: &str, cmd: &[String]) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("exec: container is required".to_string());
    }
    if cmd.is_empty() {
        return Err("exec: command is required".to_string());
    }
    let result = runtime.exec(container, cmd).map_err(|err| err.to_string())?;
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    Ok(())
}

fn handle_pull(image: &str) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    println!("pull: image={image}");
    Ok(())
}

fn handle_push(image: &str) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    println!("push: image={image}");
    Ok(())
}

fn handle_compose(file: Option<&str>, command: ComposeCommands) -> Result<(), String> {
    let path = find_compose_file(file).map_err(|err| err.to_string())?;
    let project = ComposeProject::load(&path).map_err(|err| err.to_string())?;
    match command {
        ComposeCommands::Up => {
            let order = compose_up(&project).map_err(|err| err.to_string())?;
            println!("compose up: {:?}", order);
        }
        ComposeCommands::Down => {
            let order = compose_down(&project).map_err(|err| err.to_string())?;
            println!("compose down: {:?}", order);
        }
        ComposeCommands::Ps => {
            let services = compose_ps(&project).map_err(|err| err.to_string())?;
            println!("compose ps: {:?}", services);
        }
        ComposeCommands::Logs => {
            let services = compose_logs(&project).map_err(|err| err.to_string())?;
            println!("compose logs: {:?}", services);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Commands, ComposeCommands, dispatch, handle_build, handle_containers, handle_exec,
        handle_image_prune, handle_images, handle_logs, handle_pull, handle_push, handle_rmi,
        handle_run, validate_network_backend,
    };
    use clap::Parser;
    use ferro_core::image_store::LocalImageStore;
    use ferro_core::runtime::ContainerRuntime;

    #[test]
    fn parses_run_command() {
        let cli = Cli::parse_from(["ferrocrate", "run", "alpine:latest", "echo", "hi"]);
        match cli.command {
            Commands::Run { image, cmd, network_backend } => {
                assert_eq!(image, "alpine:latest");
                assert_eq!(cmd, vec!["echo", "hi"]);
                assert_eq!(network_backend, "ebpf");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_build_command_with_tag() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "build",
            "./Dockerfile",
            "--tag",
            "acme/app:dev",
        ]);

        match cli.command {
            Commands::Build { dockerfile, tag } => {
                assert_eq!(dockerfile, "./Dockerfile");
                assert_eq!(tag.expect("tag"), "acme/app:dev");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_rmi_command() {
        let cli = Cli::parse_from(["ferrocrate", "rmi", "alpine:latest"]);
        match cli.command {
            Commands::Rmi { image } => assert_eq!(image, "alpine:latest"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_image_prune_command() {
        let cli = Cli::parse_from(["ferrocrate", "image-prune"]);
        match cli.command {
            Commands::ImagePrune => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rmi_handler_rejects_invalid_image() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let err = handle_rmi(&store, "").expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn image_prune_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        handle_image_prune(&store).expect("prune");
    }

    #[test]
    fn parses_compose_command() {
        let cli = Cli::parse_from(["ferrocrate", "compose", "up"]);
        match cli.command {
            Commands::Compose { file, command } => {
                assert!(file.is_none());
                assert!(matches!(command, ComposeCommands::Up));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_pull_and_push_commands() {
        let pull = Cli::parse_from(["ferrocrate", "pull", "ghcr.io/acme/app:latest"]);
        match pull.command {
            Commands::Pull { image } => assert_eq!(image, "ghcr.io/acme/app:latest"),
            other => panic!("unexpected command: {other:?}"),
        }

        let push = Cli::parse_from(["ferrocrate", "push", "ghcr.io/acme/app:latest"]);
        match push.command {
            Commands::Push { image } => assert_eq!(image, "ghcr.io/acme/app:latest"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn run_handler_rejects_invalid_image() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_run(&runtime, "", &[], "ebpf").expect_err("invalid reference");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn dispatch_exec_requires_command() {
        let _guard = TestRuntimeDir::new();
        let err = dispatch(Commands::Exec {
            container: "c1".to_string(),
            cmd: vec![],
        })
        .expect_err("missing command");
        assert!(err.contains("exec: command is required"));
    }

    #[test]
    fn build_handler_requires_dockerfile_path() {
        let err = handle_build("", None).expect_err("dockerfile required");
        assert!(err.contains("dockerfile path is required"));
    }

    #[test]
    fn build_handler_rejects_invalid_tag() {
        let err = handle_build("./Dockerfile", Some("")).expect_err("invalid tag");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn images_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        handle_images(&store).expect("images handler should succeed");
    }

    #[test]
    fn containers_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        handle_containers(&runtime).expect("containers handler should succeed");
    }

    #[test]
    fn logs_handler_requires_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_logs(&runtime, "").expect_err("container required");
        assert!(err.contains("logs: container is required"));
    }

    #[test]
    fn exec_handler_requires_container_and_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_exec(&runtime, "", &["/bin/sh".to_string()])
            .expect_err("container required");
        assert!(err.contains("exec: container is required"));

        let err = handle_exec(&runtime, "c1", &[]).expect_err("command required");
        assert!(err.contains("exec: command is required"));
    }

    #[test]
    fn pull_handler_rejects_invalid_image() {
        let err = handle_pull("").expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn push_handler_rejects_invalid_image() {
        let err = handle_push("").expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn network_backend_validation() {
        validate_network_backend("ebpf").expect("ok");
        validate_network_backend("iptables").expect("ok");
        validate_network_backend("nftables").expect("ok");
        let err = validate_network_backend("bogus").expect_err("invalid backend");
        assert!(err.contains("network-backend"));
    }

    struct TestRuntimeDir {
        original: Option<String>,
        _dir: tempfile::TempDir,
    }

    impl TestRuntimeDir {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let original = std::env::var("FERROCRATE_RUNTIME_DIR").ok();
            unsafe {
                std::env::set_var("FERROCRATE_RUNTIME_DIR", dir.path());
            }
            Self { original, _dir: dir }
        }
    }

    impl Drop for TestRuntimeDir {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var("FERROCRATE_RUNTIME_DIR", value);
                }
            } else {
                unsafe {
                    std::env::remove_var("FERROCRATE_RUNTIME_DIR");
                }
            }
        }
    }
}

fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("FERROCRATE_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".ferrocrate");
    }
    PathBuf::from(".ferrocrate")
}
