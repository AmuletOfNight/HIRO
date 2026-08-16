//! HIRO command-line tool: enrollment, management, diagnostics.

mod client;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use hiro_core::proto::{Op, ResultValue};

use client::{current_user_name, Client, DEFAULT_SOCKET};

#[derive(Parser, Debug)]
#[command(
    name = "hiro",
    version,
    about = "Windows Hello-style face authentication for Linux"
)]
struct Args {
    /// Daemon socket path.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enroll face templates (run in front of the IR camera).
    Enroll {
        /// User to enroll templates for (default: you).
        user: Option<String>,
        /// Maximum number of templates to add this run.
        #[arg(long, default_value_t = 8)]
        max: usize,
    },
    /// List enrolled templates.
    List {
        /// User to list (default: you).
        user: Option<String>,
    },
    /// Remove one template.
    Remove {
        /// Template id (see `hiro list`).
        id: i64,
        /// User whose template to remove (default: you).
        user: Option<String>,
    },
    /// Remove all templates for a user.
    Clear {
        /// User to clear (default: you).
        user: Option<String>,
    },
    /// Test recognition against your own templates.
    Test {
        /// PAM service name reported in the audit log.
        #[arg(long, default_value = "hiro-test")]
        service: String,
    },
    /// Capture one frame to a PGM file (debug aid).
    Snapshot { path: PathBuf },
    /// Run hardware diagnostics on this machine.
    Doctor,
    /// Show daemon status.
    Status,
    /// Ping the daemon.
    Ping,
    /// Prewarm models and camera.
    Prewarm,
    /// Reload the daemon configuration.
    Reload,
}

fn user_or_default(user: Option<String>) -> Result<String, String> {
    user.or_else(current_user_name)
        .ok_or_else(|| "cannot determine your login name; pass the user explicitly".to_string())
}

fn main() {
    let args = Args::parse();
    let mut client = Client::new(args.socket.clone());

    let result = match args.command {
        Command::Enroll { user, max } => {
            let user = user_or_default(user);
            user.and_then(|user| match client.call(Op::Enroll { user, max_models: max }) {
                Ok(ResultValue::Enroll(r)) => {
                    println!(
                        "Enrollment complete: {} templates added, {} frames rejected",
                        r.added, r.rejected
                    );
                    for (i, (id, report)) in r.template_ids.iter().zip(&r.reports).enumerate() {
                        println!(
                            "  template #{i} (id={id}) sharpness={:.1} size={:.2}% variance={:.1}",
                            report.sharpness,
                            report.size_ratio * 100.0,
                            report.variance
                        );
                    }
                    if r.added > 0 {
                        println!("Tip: verify with `hiro test`, then enable PAM integration.");
                    } else {
                        println!("No templates added - check lighting, face the camera, and run `hiro doctor`.");
                    }
                    Ok(())
                }
                Ok(_) => Err("unexpected daemon response".into()),
                Err(e) => Err(e),
            })
        }
        Command::List { user } => {
            let user = user_or_default(user);
            user.and_then(|user| match client.call(Op::List { user }) {
                Ok(ResultValue::List { templates }) => {
                    if templates.is_empty() {
                        println!("no templates enrolled");
                    } else {
                        println!("id        created   quality");
                        for t in templates {
                            let when = chrono_like(t.created_at);
                            println!(
                                "{:<9} {:<9} {}",
                                t.id,
                                when,
                                t.quality
                                    .map(|q| format!("{q:.1}"))
                                    .unwrap_or_else(|| "-".into())
                            );
                        }
                    }
                    Ok(())
                }
                Ok(_) => Err("unexpected daemon response".into()),
                Err(e) => Err(e),
            })
        }
        Command::Remove { id, user } => {
            let user = user_or_default(user);
            user.and_then(|user| {
                match client.call(Op::Remove {
                    user,
                    template_id: id,
                }) {
                    Ok(ResultValue::Removed { id }) => {
                        println!("removed template {id}");
                        Ok(())
                    }
                    Ok(_) => Err("unexpected daemon response".into()),
                    Err(e) => Err(e),
                }
            })
        }
        Command::Clear { user } => {
            let user = user_or_default(user);
            user.and_then(|user| match client.call(Op::Clear { user }) {
                Ok(ResultValue::Cleared { count }) => {
                    println!("removed {count} templates");
                    Ok(())
                }
                Ok(_) => Err("unexpected daemon response".into()),
                Err(e) => Err(e),
            })
        }
        Command::Test { service } => {
            let user = user_or_default(None);
            user.and_then(|user| {
                let started = std::time::Instant::now();
                match client.call(Op::Verify { user, service, timeout_ms: 10_000 }) {
                    Ok(ResultValue::Verify(v)) => {
                        let elapsed = started.elapsed().as_millis();
                        if v.matched {
                            println!(
                                "MATCH  score={:.3} template={:?} frames={} liveness={} ({elapsed} ms)",
                                v.score.unwrap_or(0.0),
                                v.template_id,
                                v.frames_analyzed,
                                v.liveness_ok
                            );
                        } else {
                            println!("NO MATCH  reason={} ({elapsed} ms)", v.reason);
                        }
                        Ok(())
                    }
                    Ok(_) => Err("unexpected daemon response".into()),
                    Err(e) => Err(e),
                }
            })
        }
        Command::Snapshot { path } => match client.call(Op::Snapshot {
            path: path.display().to_string(),
        }) {
            Ok(ResultValue::Snapshot { path }) => {
                println!("wrote {path} (PGM; convert with `magick {path} out.png`)");
                Ok(())
            }
            Ok(_) => Err("unexpected daemon response".into()),
            Err(e) => Err(e),
        },
        Command::Doctor => {
            doctor();
            Ok(())
        }
        Command::Status => match client.call(Op::Status) {
            Ok(ResultValue::Status(s)) => {
                println!("hirod version : {}", s.version);
                println!("uptime        : {} s", s.uptime_secs);
                println!(
                    "camera        : {}",
                    s.camera.clone().unwrap_or_else(|| "none".into())
                );
                println!(
                    "driver        : {}",
                    s.driver.clone().unwrap_or_else(|| "-".into())
                );
                println!(
                    "IR detected   : {}",
                    s.ir_detected
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".into())
                );
                println!(
                    "emitter       : {}",
                    s.emitter_active
                        .map(|v| if v { "on" } else { "off" })
                        .unwrap_or("-")
                );
                println!(
                    "pipeline      : {} (loaded={})",
                    s.pipeline, s.models_loaded
                );
                println!("templates     : {}", s.templates);
                println!(
                    "TPM           : {}",
                    s.tpm_available
                        .map(|v| if v { "yes" } else { "no" })
                        .unwrap_or("-")
                );
                Ok(())
            }
            Ok(_) => Err("unexpected daemon response".into()),
            Err(e) => Err(e),
        },
        Command::Ping => match client.call(Op::Ping) {
            Ok(ResultValue::Pong { daemon }) => {
                println!("pong from hirod {daemon}");
                Ok(())
            }
            Ok(_) => Err("unexpected daemon response".into()),
            Err(e) => Err(e),
        },
        Command::Prewarm => match client.call(Op::Prewarm) {
            Ok(ResultValue::Prewarmed) => {
                println!("prewarmed");
                Ok(())
            }
            Ok(_) => Err("unexpected daemon response".into()),
            Err(e) => Err(e),
        },
        Command::Reload => match client.call(Op::Reload) {
            Ok(ResultValue::Reloaded) => {
                println!("configuration reloaded");
                Ok(())
            }
            Ok(_) => Err("unexpected daemon response".into()),
            Err(e) => Err(e),
        },
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Format a unix timestamp as days-ago for compact display.
fn chrono_like(ts: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let delta = now - ts;
    if delta < 60 {
        "just now".into()
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

fn doctor() {
    println!("== camera discovery ==");
    let probes = hiro_hw::discover::probe_devices();
    print!("{}", hiro_hw::discover::summarize(&probes));

    let picked = hiro_hw::discover::pick_capture_device(&probes, None);
    match &picked {
        Ok(p) => println!("would use: {} ({})", p.path, p.why_ir),
        Err(e) => println!("no usable camera: {e}"),
    }

    println!();
    println!("== emitter support ==");
    if hiro_hw::emitter::external_tool_present() {
        println!("linux-enable-ir-emitter: present");
    } else {
        println!("linux-enable-ir-emitter: NOT installed (install for emitter fallback)");
    }
    let quirks = hiro_hw::quirks::QuirkDb::load(None);
    println!("built-in XU quirks: {}", quirks.len());

    println!();
    println!("== models ==");
    let manifest = match hiro_face::models::Manifest::builtin() {
        Ok(m) => m,
        Err(e) => {
            println!("manifest broken: {e}");
            return;
        }
    };
    match manifest.verify_all(&std::path::PathBuf::from("/usr/share/hiro/models")) {
        Ok(()) => println!("all models present"),
        Err(e) => println!("model check failed: {e}\nrun scripts/fetch-models.sh"),
    }

    println!();
    println!("== daemon ==");
    let mut client = Client::new(PathBuf::from(DEFAULT_SOCKET));
    match client.call(Op::Ping) {
        Ok(ResultValue::Pong { daemon }) => println!("daemon reachable (v{daemon})"),
        Ok(_) => println!("daemon gave an unexpected answer"),
        Err(e) => println!("daemon not reachable: {e}"),
    }
}
