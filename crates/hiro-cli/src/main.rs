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
    /// Manage the sealed login password used to unlock the keyring on face
    /// login (see `hiro keyring set`).
    Keyring {
        #[command(subcommand)]
        cmd: KeyringCmd,
    },
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

/// Subcommands of `hiro keyring`.
#[derive(Subcommand, Debug)]
enum KeyringCmd {
    /// Seal the login password so face login unlocks the keyring.
    ///
    /// You will be prompted twice to guard against typos. Re-run after
    /// changing your login password. The password is stored encrypted
    /// (AES-256-GCM under the TPM-sealed data key) and re-verified against
    /// the account on every face login.
    Set {
        /// User to store it for (default: you).
        user: Option<String>,
    },
    /// Drop the sealed login password.
    Clear {
        /// User to clear (default: you).
        user: Option<String>,
    },
    /// Show whether keyring unlock is configured and armed.
    Status {
        /// User to inspect (default: you).
        user: Option<String>,
    },
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
                match client.call(Op::Verify {
                    user,
                    service,
                    timeout_ms: 10_000,
                    want_keyring: false,
                }) {
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
                            match v.variance {
                                Some(_) => println!(
                                    "NO MATCH  reason={} variance={:.2} motion={:.4} ({elapsed} ms)",
                                    v.reason, v.variance.unwrap_or(0.0), v.motion.unwrap_or(0.0)
                                ),
                                None => println!("NO MATCH  reason={} ({elapsed} ms)", v.reason),
                            }
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
        Command::Keyring { cmd } => {
            match cmd {
                KeyringCmd::Set { user } => {
                    let user = user_or_default(user);
                    user.and_then(|user| {
                    println!("Enrolling your login password for keyring unlock (stored sealed).");
                    let first = read_hidden_password("Login password: ")?;
                    let second = read_hidden_password("Repeat login password: ")?;
                    if first != second {
                        return Err("passwords do not match; nothing was stored".into());
                    }
                    match client.call(Op::KeyringSet {
                        user,
                        password: first,
                    }) {
                        Ok(ResultValue::KeyringSet { stored: true }) => {
                            println!("Keyring password stored. Face login will now unlock your keyring.");
                            println!("Re-run this command after changing your login password.");
                            Ok(())
                        }
                        Ok(_) => Err("unexpected daemon response".into()),
                        Err(e) => Err(e),
                    }
                })
                }
                KeyringCmd::Clear { user } => {
                    let user = user_or_default(user);
                    user.and_then(|user| match client.call(Op::KeyringClear { user }) {
                        Ok(ResultValue::KeyringCleared { removed: true }) => {
                            println!("Sealed keyring password removed.");
                            Ok(())
                        }
                        Ok(_) => Err("no keyring password stored".into()),
                        Err(e) => Err(e),
                    })
                }
                KeyringCmd::Status { user } => {
                    let user = user_or_default(user);
                    user.and_then(|user| match client.call(Op::KeyringStatus { user }) {
                    Ok(ResultValue::KeyringStatus { enabled, stored }) => {
                        println!("keyring unlock enabled : {}", if enabled { "yes" } else { "no" });
                        println!("password stored        : {}", if stored { "yes" } else { "no" });
                        if !enabled {
                            println!("note: set [keyring] enabled = true in /etc/hiro/config.toml and restart hirod");
                        }
                        if enabled && stored {
                            println!("face login will unlock the keyring (for listed services).");
                        }
                        Ok(())
                    }
                    Ok(_) => Err("unexpected daemon response".into()),
                    Err(e) => Err(e),
                })
                }
            }
        }
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

/// Read a line from the terminal with echo disabled (termios), so the
/// login password is not visible while being typed.
fn read_hidden_password(prompt: &str) -> Result<String, String> {
    use std::io::{BufRead, Write};

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .or_else(|_| std::fs::OpenOptions::new().read(true).open("/dev/stdin"))
        .map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(&tty);
    let mut writer = std::io::BufWriter::new(&tty);
    writer
        .write_all(prompt.as_bytes())
        .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    let fd = {
        use std::os::fd::AsRawFd;
        tty.as_raw_fd()
    };
    let mut term = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err("tcgetattr failed".into());
        }
        t
    };
    let orig = term;
    term.c_lflag &= !libc::ECHO;
    unsafe {
        if libc::tcsetattr(fd, libc::TCSANOW, &term) != 0 {
            return Err("tcsetattr failed".into());
        }
    }

    let mut line = String::new();
    let read_result = reader.read_line(&mut line).map_err(|e| e.to_string());
    // Restore echo before returning, whatever happens.
    unsafe {
        let _ = libc::tcsetattr(fd, libc::TCSANOW, &orig);
    }
    read_result?;
    let _ = writer.write_all(b"\n");
    let _ = writer.flush();
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
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
