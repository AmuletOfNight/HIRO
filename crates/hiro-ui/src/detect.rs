//! UI decision for the fallback indicator: render, defer to the GNOME
//! extension, or stay disabled. The detection probes themselves live in
//! `hiro_core::ui` so the `hiro` CLI can report the same outcome.

use hiro_core::config::UiMode;
use hiro_core::ui;

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
            if ui::desktop_is_gnome() && ui::gnome_extension_enabled() {
                UiDecision::Defer
            } else {
                UiDecision::Active
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_switches() {
        assert_eq!(decide(UiMode::On), UiDecision::Active);
        assert_eq!(decide(UiMode::Off), UiDecision::Disabled);
    }

    #[test]
    fn non_gnome_desktop_is_active() {
        // With no environment, auto-detection must default to active.
        assert!(!ui::desktop_is_gnome());
        assert_eq!(decide(UiMode::Auto), UiDecision::Active);
    }
}
