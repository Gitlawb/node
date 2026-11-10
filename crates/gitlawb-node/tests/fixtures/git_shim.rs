use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let executable = std::env::current_exe()?;
    let config = std::fs::read_to_string(executable.parent().unwrap().join("config"))?;
    let (mode, parameter) = config.split_once('\n').unwrap_or((&config, ""));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if mode == "delay" {
        std::thread::sleep(Duration::from_millis(parameter.parse().unwrap()));
    }
    let batch = args.get(1).is_some_and(|arg| arg == "--batch-check");
    let input = if batch {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes)?;
        Some(bytes)
    } else {
        None
    };
    let cwd = std::env::current_dir()?;
    let hang = mode == "hang"
        || (mode == "hang-repo" && cwd.file_name().is_some_and(|name| name == parameter))
        || (mode == "hang-oid"
            && (args.iter().any(|arg| arg == parameter)
                || input
                    .as_ref()
                    .is_some_and(|bytes| String::from_utf8_lossy(bytes).trim() == parameter)));
    if hang {
        std::thread::sleep(Duration::from_secs(30));
        std::process::exit(1);
    }
    if mode == "log-types" && batch {
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(parameter)?;
        writeln!(
            log,
            "{} {}",
            String::from_utf8_lossy(input.as_ref().unwrap()).trim(),
            cwd.file_name().unwrap().to_string_lossy()
        )?;
    }
    let mut child = Command::new("git")
        .args(&args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(&bytes)?;
    }
    std::process::exit(child.wait()?.code().unwrap_or(1));
}
