//! Desktop / GNOME-extension detection shared by the session UI and the
//! `hiro` CLI.
//!
//! `hiro-ui` renders the in-session indicator and approval prompts on any
//! desktop, but defers to the GNOME Shell extension (`hiro-status@hiro`)
//! when that extension is running — otherwise both UIs would render the same
//! approval prompt. Detection uses environment hints, a `/proc` process
//! probe, and a read-only `gnome-extensions info` query; it is advisory,
//! never a security boundary.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long a `gnome-extensions info` probe may take before `hiro-ui` gives
/// up and renders. The probe is a GJS process that talks to the running
/// shell over D-Bus; in a minimal launch environment (e.g. a systemd user
/// unit) a wedged bus must not stall UI startup forever.
const EXTENSION_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Is the current session a GNOME session?
///
/// Checks `XDG_CURRENT_DESKTOP` (a colon-separated list, e.g.
/// `ubuntu:GNOME`), `DESKTOP_SESSION`, and `XDG_SESSION_DESKTOP` for a
/// GNOME entry (case-insensitive; `GNOME-Classic` and friends count), and
/// falls back to a `/proc` probe for a running `gnome-shell` process.
///
/// The env-var half alone is unreliable for process trees that do not
/// inherit the desktop session's environment (systemd user units, XDG
/// autostart), so this is diagnostics-only: the *defer* decision lives in
/// [`gnome_extension_enabled`], never here.
pub fn desktop_is_gnome() -> bool {
    desktop_is_gnome_with(|v| std::env::var(v)) || gnome_shell_running()
}

/// Same as [`desktop_is_gnome`] with an injectable variable reader (for
/// tests and for callers that already have an environment).
fn desktop_is_gnome_with(get: impl Fn(&str) -> Result<String, std::env::VarError>) -> bool {
    for var in [
        "XDG_CURRENT_DESKTOP",
        "DESKTOP_SESSION",
        "XDG_SESSION_DESKTOP",
    ] {
        if let Ok(value) = get(var) {
            if value_is_gnome(&value) {
                return true;
            }
        }
    }
    false
}

/// Does a single XDG desktop value denote a GNOME session?
fn value_is_gnome(value: &str) -> bool {
    value
        .split(':')
        .any(|entry| entry.trim().to_ascii_lowercase().starts_with("gnome"))
}

/// Is a `gnome-shell` process running? Best-effort `/proc` scan; used only
/// for diagnostics (the defer decision never rests on it).
pub fn gnome_shell_running() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() == "gnome-shell" {
            return true;
        }
    }
    false
}

/// Should the fallback UI defer to the GNOME Shell extension?
///
/// True when `gnome-extensions info hiro-status@hiro` reports the extension
/// as enabled. That query runs against the *running* shell over D-Bus, so an
/// `ENABLED` answer is only possible while GNOME Shell is up with the
/// extension active — no desktop-environment hints are consulted. This keeps
/// `hiro-ui` from double-rendering on GNOME even when it was started by a
/// systemd user unit that never inherited `XDG_CURRENT_DESKTOP` and friends.
///
/// Returns `false` whenever the command is unavailable, times out, or errors
/// — a missing binary, unreachable bus, or disabled extension means there is
/// nothing to defer to, so the fallback should render.
pub fn gnome_extension_enabled() -> bool {
    let mut child = match Command::new("gnome-extensions")
        .arg("info")
        .arg("hiro-status@hiro")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let stdout = child.stdout.take();
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut out) = stdout {
            let _ = out.read_to_string(&mut text);
        }
        let _ = tx.send(text);
    });
    match rx.recv_timeout(EXTENSION_PROBE_TIMEOUT) {
        Ok(text) => {
            // The reader only finishes once the pipe hits EOF, so the child
            // has exited by the time we get here; `wait` reaps it.
            let _ = child.wait();
            let _ = reader.join();
            extension_state_enabled(&text)
        }
        Err(_) => {
            // The probe hung (no D-Bus, stalled shell, ...). Kill it so no
            // stray GJS process lingers, and treat it as "no extension".
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            false
        }
    }
}

/// Does `gnome-extensions info` output denote an enabled extension?
///
/// The report format changed between shell versions: older `gnome-extensions`
/// printed `State: ENABLED`, while GNOME 45+ prints an `Enabled: Yes` flag
/// plus a runtime `State: ACTIVE` line. Both are accepted. An extension that
/// is enabled but stuck in `ERROR`/`OUT_OF_DATE` does not count — it cannot
/// render the UI, so the fallback should.
fn extension_state_enabled(output: &str) -> bool {
    let mut state = String::new();
    let mut enabled_flag: Option<String> = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("State:") {
            state = rest.trim().to_ascii_lowercase();
        } else if let Some(rest) = line.strip_prefix("Enabled:") {
            enabled_flag = Some(rest.trim().to_ascii_lowercase());
        }
    }
    match enabled_flag.as_deref() {
        // Older shells only reported `State: ENABLED` (or DISABLED/ERROR).
        None => matches!(state.as_str(), "enabled" | "active"),
        // GNOME 45+: the `Enabled:` flag is authoritative, but a broken
        // runtime state means the extension cannot render.
        Some(flag) => {
            matches!(flag, "yes" | "true") && !matches!(state.as_str(), "error" | "out_of_date")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_gnome_environment_is_not_gnome() {
        // No GNOME hints -> not GNOME (the reader returns Err).
        assert!(!desktop_is_gnome_with(|_| Err(
            std::env::VarError::NotPresent
        )));
    }

    #[test]
    fn gnome_desktop_detection_parses_colon_lists() {
        // "ubuntu:GNOME" must count as GNOME, "ubuntu:gnome" too,
        // "GNOME-Classic" and "GNOME-Classic:xorg" too, and "KDE" must not.
        let cases = [
            ("ubuntu:GNOME", true),
            ("GNOME", true),
            ("ubuntu:gnome", true),
            ("GNOME-Classic", true),
            ("GNOME-Classic:xorg", true),
            ("KDE", false),
            ("XFCE", false),
            ("", false),
        ];
        for (value, expected) in cases {
            let get = |var: &str| -> Result<String, std::env::VarError> {
                if var == "XDG_CURRENT_DESKTOP" {
                    Ok(value.to_string())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            };
            assert_eq!(desktop_is_gnome_with(get), expected, "entry {value:?}");
        }
    }

    #[test]
    fn extension_state_line_parsing() {
        // Old gnome-extensions format (`State: ENABLED`).
        assert!(extension_state_enabled("hiro-status@hiro\n  State: ENABLED\n"));
        assert!(extension_state_enabled("hiro-status@hiro\n  State: enabled\n"));
        assert!(!extension_state_enabled("hiro-status@hiro\n  State: DISABLED\n"));
        assert!(!extension_state_enabled("error: No such extension\n"));
        assert!(!extension_state_enabled(""));
        // GNOME 45+ format (`Enabled: Yes` + runtime `State: ACTIVE`).
        assert!(extension_state_enabled(
            "hiro-status@hiro\n  Enabled: Yes\n  State: ACTIVE\n"
        ));
        assert!(extension_state_enabled(
            "hiro-status@hiro\n  Enabled: yes\n  State: active\n"
        ));
        assert!(!extension_state_enabled(
            "hiro-status@hiro\n  Enabled: No\n  State: INACTIVE\n"
        ));
        // Enabled but errored -> cannot render, so do not defer to it.
        assert!(!extension_state_enabled(
            "hiro-status@hiro\n  Enabled: Yes\n  State: ERROR\n"
        ));
    }
}
