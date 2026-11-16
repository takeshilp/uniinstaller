//! Read-only CLI: list, show, plan, history, plus sandbox-seed / sandbox-clean (sandbox only).
use std::path::PathBuf;
use uni_core::env::{Env, SANDBOX_VAR};
use uni_core::{inventory, sandbox};

fn sandbox_dir() -> Result<PathBuf, String> {
    let v = std::env::var_os(SANDBOX_VAR).ok_or(format!("{SANDBOX_VAR} is not set"))?;
    let p = PathBuf::from(v);
    if !uni_core::paths::is_local_abs(&p) {
        return Err(format!("{SANDBOX_VAR} must be a local absolute path"));
    }
    Ok(p)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "sandbox-seed" => {
            let dir = sandbox_dir()?;
            sandbox::seed(&dir, "sandbox").map_err(|e| e.0)?;
            println!("sandbox seeded at {}", dir.display());
        }
        "sandbox-clean" => {
            let dir = sandbox_dir()?;
            sandbox::clean(&dir, "sandbox").map_err(|e| e.0)?;
            println!("sandbox cleaned: {}", dir.display());
        }
        "list" => {
            let env = Env::from_process_env().map_err(|e| e.0)?;
            let apps = inventory::list_apps(&env).map_err(|e| e.0)?;
            if args.iter().any(|a| a == "--json") {
                println!("{}", serde_json::to_string_pretty(&apps).map_err(|e| e.to_string())?);
            } else {
                for a in &apps {
                    println!(
                        "{}\t{}\t{}\t{}",
                        a.id,
                        a.display_name,
                        a.display_version.as_deref().unwrap_or("-"),
                        a.publisher.as_deref().unwrap_or("-")
                    );
                }
                eprintln!("{} programs{}", apps.len(), if env.sandbox { " (sandbox)" } else { "" });
            }
        }
        _ => println!("uni {}\nusage: uni list [--json] | show <id> | plan <id> | history | sandbox-seed | sandbox-clean", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
