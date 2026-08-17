//! `hiro-ui` — desktop-agnostic status indicator and approval prompt.
//!
//! Runs in the user's graphical session (systemd user unit or XDG
//! autostart), watches the `hirod` state stream, and renders scanning
//! progress, Allow/Deny approval prompts, and result flashes on any desktop.
//! Defers to the GNOME Shell extension when that is the active UI.

mod app;
mod detect;
mod face;
mod socket;
mod state;

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use glib::ControlFlow;

use crate::app::App;
use crate::detect::{decide, UiDecision};
use crate::socket::SocketMsg;

#[derive(Parser, Debug)]
#[command(
    name = "hiro-ui",
    version,
    about = "Desktop-agnostic status indicator and approval prompt for HIRO"
)]
struct Args {
    /// Daemon socket path.
    #[arg(long, default_value = "/run/hirod/hirod.sock")]
    socket: PathBuf,
    /// Configuration file (defaults are used when missing or unreadable).
    #[arg(long, default_value = "/etc/hiro/config.toml")]
    config: PathBuf,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if !single_instance() {
        log::info!("another hiro-ui instance is running; exiting");
        std::process::exit(0);
    }

    let cfg = load_config(&args.config);
    match decide(cfg.ui.active) {
        UiDecision::Disabled => {
            log::info!("ui disabled by config ([ui] active = \"off\"); exiting");
            std::process::exit(0);
        }
        UiDecision::Defer => {
            log::info!("GNOME Shell extension hiro-status@hiro is enabled; deferring to it");
            std::process::exit(0);
        }
        UiDecision::Active => {}
    }

    if gtk::init().is_err() {
        eprintln!("hiro-ui: cannot initialize GTK (is DISPLAY/WAYLAND_DISPLAY set?)");
        std::process::exit(1);
    }

    let app = App::new(args.socket.clone());

    // Marshal daemon events from the reader thread into the GTK loop: the
    // socket thread sends over an mpsc channel and a periodic poller drains
    // it on the main thread.
    let (tx, rx) = std::sync::mpsc::channel::<SocketMsg>();
    {
        let app = app.clone();
        let _poller = glib::timeout_add_local(Duration::from_millis(50), move || {
            while let Ok(msg) = rx.try_recv() {
                let mut app = app.borrow_mut();
                match msg {
                    SocketMsg::Event(ev) => app.on_event(&ev),
                    SocketMsg::Disconnected => app.on_disconnected(),
                }
            }
            ControlFlow::Continue
        });
    }
    socket::spawn(&args.socket, tx);

    log::info!("hiro-ui ready (socket {})", args.socket.display());
    gtk::main();
}

/// Take an exclusive flock on `$XDG_RUNTIME_DIR/hiro-ui.lock` so a systemd
/// user unit and an XDG autostart entry can never run two UIs at once.
/// Returns false when another instance holds the lock.
fn single_instance() -> bool {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join("hiro-ui.lock");
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            log::warn!("cannot open lock file {path:?}: {e}; running without the guard");
            return true;
        }
    };
    let fd = file.as_raw_fd();
    // SAFETY: fd is a valid open descriptor; flock is a syscall.
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return false;
    }
    // Deliberately leak the File: dropping it would release the lock, and
    // we want it held for the whole process lifetime.
    std::mem::forget(file);
    true
}

fn load_config(path: &Path) -> hiro_core::Config {
    match std::fs::read_to_string(path) {
        Ok(text) => match hiro_core::config::Config::from_toml(&text) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("bad config {}: {e}; using defaults", path.display());
                hiro_core::Config::default()
            }
        },
        Err(_) => hiro_core::Config::default(),
    }
}
