use clap::{Parser, Subcommand};
use ferro_core::registry::parse_image_reference;
use std::process;

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
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Build {
        dockerfile: String,
        #[arg(short, long)]
        tag: Option<String>,
    },
    Images,
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
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn dispatch(command: Commands) -> Result<(), String> {
    match command {
        Commands::Run { image, cmd } => handle_run(&image, &cmd),
        Commands::Build { dockerfile, tag } => handle_build(&dockerfile, tag.as_deref()),
        Commands::Images => handle_images(),
        Commands::Containers => handle_containers(),
        Commands::Logs { container } => handle_logs(&container),
        Commands::Exec { container, cmd } => handle_exec(&container, &cmd),
        Commands::Pull { image } => {
            parse_image_reference(&image).map_err(|err| err.to_string())?;
            println!("pull: image={image}");
            Ok(())
        }
        Commands::Push { image } => {
            parse_image_reference(&image).map_err(|err| err.to_string())?;
            println!("push: image={image}");
            Ok(())
        }
    }
}

fn handle_run(image: &str, cmd: &[String]) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    if cmd.is_empty() {
        println!("run: image={image} cmd=<default>");
    } else {
        println!("run: image={image} cmd={}", cmd.join(" "));
    }
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

fn handle_images() -> Result<(), String> {
    println!("images: no entries (stub)");
    Ok(())
}

fn handle_containers() -> Result<(), String> {
    println!("containers: no entries (stub)");
    Ok(())
}

fn handle_logs(container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("logs: container is required".to_string());
    }
    println!("logs: container={container}");
    Ok(())
}

fn handle_exec(container: &str, cmd: &[String]) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("exec: container is required".to_string());
    }
    if cmd.is_empty() {
        return Err("exec: command is required".to_string());
    }
    println!("exec: container={container} cmd={}", cmd.join(" "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Commands, dispatch, handle_build, handle_containers, handle_exec, handle_images,
        handle_logs, handle_run,
    };
    use clap::Parser;

    #[test]
    fn parses_run_command() {
        let cli = Cli::parse_from(["ferrocrate", "run", "alpine:latest", "echo", "hi"]);
        match cli.command {
            Commands::Run { image, cmd } => {
                assert_eq!(image, "alpine:latest");
                assert_eq!(cmd, vec!["echo", "hi"]);
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
        let err = handle_run("", &[]).expect_err("invalid reference");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn dispatch_exec_requires_command() {
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
        handle_images().expect("images handler should succeed");
    }

    #[test]
    fn containers_handler_runs() {
        handle_containers().expect("containers handler should succeed");
    }

    #[test]
    fn logs_handler_requires_container() {
        let err = handle_logs("").expect_err("container required");
        assert!(err.contains("logs: container is required"));
    }

    #[test]
    fn exec_handler_requires_container_and_command() {
        let err = handle_exec("", &["/bin/sh".to_string()]).expect_err("container required");
        assert!(err.contains("exec: container is required"));

        let err = handle_exec("c1", &[]).expect_err("command required");
        assert!(err.contains("exec: command is required"));
    }
}
