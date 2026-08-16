//! Daemon-side audit logging.
//!
//! Every authentication verdict and administrative action is written to
//! the journal (target `hiro_audit`) and mirrored to the SQLite event
//! table. Inspect with `journalctl -t hirod -g hiro_audit`.

use hiro_store::Store;

pub fn audit(store: &Store, user: Option<&str>, action: &str, detail: &str) {
    let line = serde_json::json!({
        "user": user,
        "action": action,
        "detail": detail,
    });
    log::info!(target: "hiro_audit", "{}", line);
    if let Err(e) = store.record_event(user, action, detail) {
        log::warn!("cannot persist audit event: {e}");
    }
}
