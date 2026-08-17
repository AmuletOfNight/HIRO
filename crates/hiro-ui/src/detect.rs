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
            // `gnome-extensions info` reports the extension's state against
            // the *running* shell: an `ENABLED` answer is only possible when
            // GNOME Shell is up with the extension active, so it alone
            // decides the deferral. Desktop-environment hints
            // (XDG_CURRENT_DESKTOP & friends) are deliberately NOT consulted
            // here: systemd user units and XDG-autostart launches rarely
            // inherit them, which used to make hiro-ui render on top of the
            // extension in GNOME sessions.
            if ui::gnome_extension_enabled() {
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
    fn auto_defers_only_when_extension_is_enabled() {
        // `Auto` can only ever defer to an *enabled* extension; without one,
        // it must render no matter what desktop this machine reports.
        if !ui::gnome_extension_enabled() {
            assert_eq!(decide(UiMode::Auto), UiDecision::Active);
        }
    }
}
