//! HIRO authentication daemon.
//!
//! Owns the IR camera, face models, and encrypted template store. Serves
//! `pam_hiro.so` and the `hiro` CLI over a Unix socket at
//! `/run/hirod/hirod.sock` (configurable).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;

use hirod::state::{Daemon, DaemonOptions};

#[derive(Parser, Debug)]
#[command(name = "hirod", version, about = "HIRO face-authentication daemon")]
struct Args {
    /// Configuration file path.
    #[arg(long, default_value = "/etc/hiro/config.toml")]
    config: PathBuf,
    /// Create the encryption key file and template database, then exit.
    #[arg(long)]
    init_keys: bool,
    /// Prewarm the models and camera, then exit (install-time check).
    #[arg(long)]
    prewarm: bool,
}

fn load_config(path: &std::path::Path) -> hiro_core::Config {
    match std::fs::read_to_string(path) {
        Ok(text) => match hiro_core::Config::from_toml(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("configuration error: {e}");
                std::process::exit(1);
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::warn!("{} not found; using built-in defaults", path.display());
            hiro_core::Config::default()
        }
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

fn init_keys(cfg: &hiro_core::Config) -> ! {
    if let Some(parent) = cfg.storage.key_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("cannot create {}: {e}", parent.display());
            std::process::exit(1);
        }
    }
    match hiro_tpm::create(&cfg.storage.key_path) {
        Ok(_) => println!("created key file {}", cfg.storage.key_path.display()),
        Err(e) => {
            eprintln!("key initialization failed: {e}");
            std::process::exit(1);
        }
    }
    match hiro_store::Store::open(&cfg.storage.db_path) {
        Ok(_) => println!(
            "initialized template database {}",
            cfg.storage.db_path.display()
        ),
        Err(e) => {
            eprintln!("database initialization failed: {e}");
            std::process::exit(1);
        }
    }
    std::process::exit(0)
}

fn main() {
    let args = Args::parse();
    let cfg = load_config(&args.config);

    let level = cfg.daemon.log_level.clone();
    let mut builder = env_logger::Builder::new();
    builder.parse_filters(&level);
    builder.format_timestamp_millis();
    builder.init();

    if args.init_keys {
        init_keys(&cfg);
    }

    if !nix::unistd::geteuid().is_root() {
        eprintln!("hirod must run as root");
        std::process::exit(1);
    }

    let key_manager = match hiro_tpm::load(&cfg.storage.key_path) {
        Ok(km) => km,
        Err(e) => {
            eprintln!("cannot load encryption key: {e}");
            eprintln!("run `hirod --init-keys` once to create it");
            std::process::exit(1);
        }
    };

    let pipeline = match hiro_face::create(&cfg.recognition) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot load recognition pipeline: {e}");
            eprintln!("run scripts/fetch-models.sh and verify /usr/share/hiro/models");
            std::process::exit(1);
        }
    };

    let daemon = match Daemon::build(
        cfg,
        DaemonOptions {
            camera_source: None,
            pipeline: Some(pipeline),
            key_manager: Some(key_manager),
            store: None,
            config_path: Some(args.config),
        },
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("daemon startup failed: {e}");
            std::process::exit(1);
        }
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        signal_hook::flag::register(signal_hook::consts::SIGTERM, flag).ok();
    }
    {
        let flag = shutdown.clone();
        signal_hook::flag::register(signal_hook::consts::SIGINT, flag).ok();
    }

    let reaper = hirod::camera::spawn_reaper(daemon.camera.clone());

    if args.prewarm {
        match daemon.camera.lock() {
            Ok(mut cam) => match cam.acquire() {
                Ok(()) => {
                    cam.release();
                    println!("camera prewarmed: {}", cam.describe());
                    return;
                }
                Err(e) => {
                    eprintln!("prewarm failed: {e}");
                    std::process::exit(1);
                }
            },
            Err(_) => std::process::exit(1),
        }
    }

    if let Err(e) = hirod::server::serve(daemon.clone(), shutdown.clone()) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }

    log::info!("shutting down");
    if let Ok(mut cam) = daemon.camera.lock() {
        cam.close();
    }
    let _ = reaper.join();
}
