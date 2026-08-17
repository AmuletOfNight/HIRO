//! Desktop / GNOME-extension detection for the fallback UI.
//!
//! `hiro-ui` renders the in-session indicator and approval prompts on any
//! desktop, but must defer to the GNOME Shell extension (`hiro-status@hiro`)
//! when that extension is running — otherwise both UIs would render the same
//! approval prompt. Detection uses only environment hints and a read-only
//! `gnome-extensions info` probe; it is advisory, never a security boundary.

use hiro_core::config::UiMode;

/// What `hiro-ui` should do with the session UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiDecision {
    /// Render the in-session indicator / approval prompts.
    Active,
    /// Do not render: the GNOME Shell extension owns the UI here.
    Defer,
    /// Do not render: disabled by configuration.
    Disabled,
}

/// Decide whether the fallback UI should render, given the configured mode.
pub fn decide(mode: UiMode) -> UiDecision {
    match mode {
        UiMode::Off => UiDecision::Disabled,
        UiMode::On => UiDecision::Active,
        UiMode::Auto => {
            if desktop_is_gnome() && gnome_extension_enabled() {
                UiDecision::Defer
            } else {
                UiDecision::Active
            }
        }
    }
}

/// Is the current session a GNOME session, by XDG hints?
///
/// Checks `XDG_CURRENT_DESKTOP` (a colon-separated list, e.g.
/// `ubuntu:GNOME`), `DESKTOP_SESSION`, and `XDG_SESSION_DESKTOP` for a
/// GNOME entry (case-insensitive; `GNOME-Classic` and friends count).
pub fn desktop_is_gnome() -> bool {
    desktop_is_gnome_with(|v| std::env::var(v))
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

/// Is the `hiro-status@hiro` Shell extension enabled for this user?
///
/// Runs `gnome-extensions info hiro-status@hiro` (a read-only per-user
/// query) and looks for an enabled state. Returns `false` whenever the
/// command is unavailable or errors — a missing binary or extension means
/// there is nothing to defer to, so the fallback should render.
pub fn gnome_extension_enabled() -> bool {
    let output = match std::process::Command::new("gnome-extensions")
        .arg("info")
        .arg("hiro-status@hiro")
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&output);
    text.lines().any(|line| {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("State:") else {
            return false;
        };
        rest.trim().eq_ignore_ascii_case("enabled")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_gnome_desktop_is_active() {
        // No GNOME hints -> active (the environment reader returns Err).
        assert!(!desktop_is_gnome_with(|_| Err(
            std::env::VarError::NotPresent
        )));
        assert_eq!(decide(UiMode::Auto), UiDecision::Active);
    }

    #[test]
    fn gnome_desktop_detection_parses_colon_lists() {
        // Simulate the environment by injecting a variable reader:
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
    fn mode_switches() {
        assert_eq!(decide(UiMode::On), UiDecision::Active);
        assert_eq!(decide(UiMode::Off), UiDecision::Disabled);
    }

    #[test]
    fn extension_state_line_parsing() {
        // Match the same logic used on `gnome-extensions info` output.
        fn enabled(text: &str) -> bool {
            text.lines().any(|line| {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("State:") else {
                    return false;
                };
                rest.trim().eq_ignore_ascii_case("enabled")
            })
        }
        assert!(enabled("hiro-status@hiro\n  State: ENABLED\n"));
        assert!(enabled("hiro-status@hiro\n  State: enabled\n"));
        assert!(!enabled("hiro-status@hiro\n  State: DISABLED\n"));
        assert!(!enabled("error: No such extension\n"));
        assert!(!enabled(""));
    }
}
