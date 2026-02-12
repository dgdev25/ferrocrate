use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(name = "ferro-desktop", version, about = "FerroCrate desktop daemon/proxy")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Daemon {
        #[arg(long, default_value = "127.0.0.1:4288")]
        addr: String,
        #[arg(long)]
        wsl_distro: Option<String>,
    },
    Exec {
        #[arg(long, default_value = "127.0.0.1:4288")]
        addr: String,
        #[arg(long)]
        wsl: bool,
        #[arg(long)]
        wsl_distro: Option<String>,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Doctor {
        #[arg(long)]
        wsl_distro: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecRequest {
    cmd: Vec<String>,
    use_wsl: bool,
    wsl_distro: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecResponse {
    status: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Error)]
enum DesktopError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid request: {0}")]
    Invalid(String),
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Daemon { addr, wsl_distro } => run_daemon(&addr, wsl_distro),
        Commands::Exec {
            addr,
            wsl,
            wsl_distro,
            cmd,
        } => run_client_exec(&addr, cmd, wsl, wsl_distro),
        Commands::Doctor { wsl_distro } => run_doctor(wsl_distro),
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run_daemon(addr: &str, default_wsl_distro: Option<String>) -> Result<(), DesktopError> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let _ = handle_client(&mut stream, default_wsl_distro.as_deref());
    }
    Ok(())
}

fn handle_client(
    stream: &mut TcpStream,
    default_wsl_distro: Option<&str>,
) -> Result<(), DesktopError> {
    let mut request_line = String::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        let bytes = reader.read_line(&mut request_line)?;
        if bytes == 0 {
            return Err(DesktopError::Invalid("empty request".to_string()));
        }
    }
    let mut request: ExecRequest = serde_json::from_str(request_line.trim())?;
    if request.cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }
    if request.wsl_distro.is_none() {
        request.wsl_distro = default_wsl_distro.map(ToOwned::to_owned);
    }

    let output = run_request(&request)?;
    let response = ExecResponse {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    };
    let payload = serde_json::to_string(&response)? + "\n";
    stream.write_all(payload.as_bytes())?;
    Ok(())
}

fn run_client_exec(
    addr: &str,
    cmd: Vec<String>,
    wsl: bool,
    wsl_distro: Option<String>,
) -> Result<(), DesktopError> {
    if cmd.is_empty() {
        return Err(DesktopError::Invalid("command is required".to_string()));
    }
    let request = ExecRequest {
        cmd,
        use_wsl: wsl,
        wsl_distro,
    };
    let mut stream = TcpStream::connect(addr)?;
    let payload = serde_json::to_string(&request)? + "\n";
    stream.write_all(payload.as_bytes())?;

    let mut response_raw = String::new();
    stream.read_to_string(&mut response_raw)?;
    let response: ExecResponse = serde_json::from_str(response_raw.trim())?;

    if !response.stdout.is_empty() {
        print!("{}", response.stdout);
    }
    if !response.stderr.is_empty() {
        eprint!("{}", response.stderr);
    }
    if response.status != 0 {
        return Err(DesktopError::Invalid(format!(
            "remote command exited with status {}",
            response.status
        )));
    }
    Ok(())
}

fn run_doctor(wsl_distro: Option<String>) -> Result<(), DesktopError> {
    #[cfg(windows)]
    {
        let output = Command::new("wsl.exe").args(["-l", "-q"]).output()?;
        let status = output.status.code().unwrap_or(-1);
        println!("wsl_detected=true");
        println!("wsl_list_status={status}");
        println!("wsl_distros={}", String::from_utf8_lossy(&output.stdout).trim());
        if let Some(distro) = wsl_distro {
            let ok = String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == distro);
            println!("wsl_distro_requested={distro}");
            println!("wsl_distro_available={ok}");
        }
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        println!("wsl_detected=false");
        if let Some(distro) = wsl_distro {
            println!("wsl_distro_requested={distro}");
            println!("wsl_distro_available=false");
        }
        Ok(())
    }
}

fn run_request(request: &ExecRequest) -> Result<std::process::Output, DesktopError> {
    if request.use_wsl {
        return run_wsl_command(request);
    }
    let (program, args) = request
        .cmd
        .split_first()
        .ok_or_else(|| DesktopError::Invalid("command is required".to_string()))?;
    Ok(Command::new(program).args(args).output()?)
}

fn run_wsl_command(request: &ExecRequest) -> Result<std::process::Output, DesktopError> {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("wsl.exe");
        if let Some(distro) = request.wsl_distro.as_deref() {
            cmd.arg("--distribution").arg(distro);
        }
        cmd.arg("--");
        for arg in &request.cmd {
            cmd.arg(arg);
        }
        return Ok(cmd.output()?);
    }

    #[cfg(not(windows))]
    {
        let _ = request;
        Err(DesktopError::Invalid(
            "WSL execution is only available on Windows hosts".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecRequest, run_request};

    #[test]
    fn executes_local_command() {
        let req = ExecRequest {
            cmd: vec!["sh".to_string(), "-c".to_string(), "echo ok".to_string()],
            use_wsl: false,
            wsl_distro: None,
        };
        let out = run_request(&req).expect("run command");
        assert!(out.status.success());
    }
}
