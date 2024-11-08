use std::error::Error;
use std::process::{Command, Output, Stdio};

fn run_command(cmd: &str, args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        println!(
            "{} {} output:\n{}",
            cmd,
            args.join(" "),
            String::from_utf8_lossy(&output.stdout)
        );
    } else {
        eprintln!(
            "{} {} failed:\n{}",
            cmd,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(output)
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Running 'nargo execute'...");
    run_command("nargo", &["--version"])?;

    println!("Running 'bb prove'...");
    run_command("bb", &["--version"])?;

    Ok(())
}
