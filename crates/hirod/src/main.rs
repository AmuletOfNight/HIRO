//! HIRO authentication daemon.
//!
//! Owns the IR camera, face models, and encrypted template store. Serves
//! `pam_hiro.so` and the `hiro` CLI over a Unix socket at
//! `/run/hirod/hirod.sock` (configurable).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

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

    // Every operational mode (including --init-keys, which creates the
    // encryption key file and template database) requires root.
    if !nix::unistd::geteuid().is_root() {
        eprintln!("hirod must run as root");
        std::process::exit(1);
    }

    if args.init_keys {
        init_keys(&cfg);
    }

    // Secure-desktop mode depends on the hiro-approve helper. Warn loudly at
    // startup (not just at each approval) when it is missing, otherwise every
    // approval silently times out with no visible prompt.
    if cfg.approval.secure_desktop && !cfg.approval.secure_dialog.exists() {
        eprintln!(
            "warning: approval.secure_desktop is enabled but the dialog helper {} does not exist",
            cfg.approval.secure_dialog.display()
        );
        eprintln!(
            "         approval prompts will time out unseen; install it with `sudo ./scripts/redeploy.sh`"
        );
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
            password_checker: None,
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

    let reaper = hirod::camera::spawn_reaper(daemon.camera.clone(), shutdown.clone());

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
    close_camera_bounded(&daemon.camera);
    join_reaper_bounded(reaper);
}

/// Close the camera with a short grace period for an in-flight request to
/// release it. If the camera stays busy (e.g. a verify is mid-frame), skip
/// the clean close: the kernel reclaims the V4L2 device on process exit.
fn close_camera_bounded(camera: &Arc<Mutex<hirod::camera::CameraSession>>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Ok(mut cam) = camera.try_lock() {
            cam.close();
            return;
        }
        if std::time::Instant::now() >= deadline {
            log::warn!("camera busy; skipping clean close on shutdown");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// The reaper exits on its own once `shutdown` is set (within one poll
/// interval). Join it with a bound so a stuck driver can't stall systemd's
/// stop timeout indefinitely.
fn join_reaper_bounded(reaper: std::thread::JoinHandle<()>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !reaper.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if reaper.is_finished() {
        if reaper.join().is_err() {
            log::warn!("camera reaper panicked during shutdown");
        }
    } else {
        log::warn!("camera reaper did not exit within 3s; detaching");
    }
}
