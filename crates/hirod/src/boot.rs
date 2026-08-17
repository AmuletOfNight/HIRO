//! Boot identity for the after-reboot password gate.
//!
//! `require_password_after_boot` refuses face auth for a user until they
//! log in during the current boot. The gate keys its persisted state by
//! the kernel boot id, so it survives daemon restarts mid-boot
//! (suspend/resume via `hirod-resume.service`, crashes) but is wiped by an
//! actual reboot.

/// The kernel's boot id, stable for the lifetime of the current boot.
///
/// Falls back to a synthetic per-process id when unreadable; in that case
/// the gate degrades to "reset on every daemon start", which still enforces
/// the password-after-reboot property (just less gracefully across daemon
/// restarts within a boot).
pub fn current_boot_id() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            log::warn!(
                "cannot read kernel boot id ({e}); \
                 after-reboot gate will reset on every daemon restart"
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("synthetic-{now:x}-{}", std::process::id())
        }
    }
}
