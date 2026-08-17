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
use hiro_core::config::UiMode;
use hiro_core::ui;

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
            // Mode is "off": if a forced "on" run earlier disabled the GNOME
            // Shell extension, hand control back to it before exiting.
            restore_extension_if_marked();
            log::info!("ui disabled by config ([ui] active = \"off\"); exiting");
            std::process::exit(0);
        }
        UiDecision::Defer => {
            // Mode is "auto" and the extension is enabled; drop any stale
            // marker from a previous forced run and defer to the extension.
            clear_extension_marker();
            log::info!("GNOME Shell extension hiro-status@hiro is enabled; deferring to it");
            std::process::exit(0);
        }
        UiDecision::Active => {
            if cfg.ui.active == UiMode::On {
                // Forced mode: the extension would render the same
                // scan/approval overlay on top of the GTK card, so disable
                // it (best-effort) before rendering.
                if ui::gnome_extension_disable() {
                    mark_extension_disabled();
                    log::info!("hiro-status@hiro disabled ([ui] active = \"on\")");
                } else {
                    log::warn!(
                        "could not disable hiro-status@hiro; the GNOME Shell extension may still overlay hiro-ui"
                    );
                }
            } else if let Some(ok) = restore_extension_if_marked() {
                // Mode is "auto" and the extension is off because a forced
                // "on" run disabled it: hand control back to the extension.
                if ok {
                    log::info!(
                        "hiro-status@hiro re-enabled ([ui] active = \"auto\"); deferring to it"
                    );
                    std::process::exit(0);
                }
                // Re-enabling failed: keep rendering the fallback UI rather
                // than leave the session without any indicator.
            }
        }
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

/// Marker file recording that this session's `hiro-ui` disabled the
/// `hiro-status@hiro` GNOME Shell extension while `[ui] active = "on"`.
/// A later run in `auto`/`off` mode uses it to hand control back to the
/// extension (re-enabling it) instead of leaving it switched off.
fn extension_marker_path() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    dir.join("hiro-ui-extension-disabled")
}

fn mark_extension_disabled() {
    if let Err(e) = std::fs::write(extension_marker_path(), b"") {
        log::warn!("cannot write extension marker {}: {e}", extension_marker_path().display());
    }
}

fn clear_extension_marker() {
    let _ = std::fs::remove_file(extension_marker_path());
}

/// If a previous forced (`[ui] active = "on"`) run disabled the GNOME Shell
/// extension, re-enable it and forget the marker so the extension owns the
/// UI again. Returns `None` when there was no marker, `Some(true)` when the
/// extension is on afterwards (re-enabled here or already was), and
/// `Some(false)` when re-enabling failed.
fn restore_extension_if_marked() -> Option<bool> {
    if !extension_marker_path().exists() {
        return None;
    }
    let ok = ui::gnome_extension_enable();
    clear_extension_marker();
    if ok {
        log::info!("re-enabled hiro-status@hiro (handing control back to the extension)");
    } else {
        log::warn!(
            "could not re-enable hiro-status@hiro; run `gnome-extensions enable hiro-status@hiro` manually"
        );
    }
    Some(ok)
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
