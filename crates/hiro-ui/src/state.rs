//! Human-readable failure reasons and immediacy classification.
//!
//! Ports of the GNOME Shell extension's `_reasonLabel` / `_isImmediateFailure`
//! so the fallback UI says the same thing the extension says.

/// Map a daemon reason code to a human-readable sentence.
///
/// Returns `None` when the reason is unrecognized, letting the caller fall
/// back to a generic verdict (e.g. "Not recognized").
pub fn reason_label(reason: Option<&str>) -> Option<String> {
    let r = reason.unwrap_or("").to_lowercase();
    if r.contains("approval_denied") || r.contains("approval denied") {
        return Some("Approval denied".into());
    }
    if r.contains("approval_timeout") || r.contains("approval timed out") {
        return Some("Approval timed out — try again".into());
    }
    if r.contains("rate_limited") || r.contains("rate limited") {
        return Some("Rate limited — please wait a moment".into());
    }
    if r.contains("locked_out") || r.contains("locked out") {
        return Some("Too many attempts — try again later".into());
    }
    if r.contains("password_required") || r.contains("password required") {
        return Some("Enter your password first".into());
    }
    if r.contains("liveness_failed") || r.contains("liveness") {
        return Some("Not enough movement — try again and move your head slightly".into());
    }
    if r.contains("no_face") {
        return Some("No face detected".into());
    }
    if r.contains("face_too_small") {
        return Some("Face too small — move closer to the camera".into());
    }
    if r.contains("blurry") {
        return Some("Too blurry — hold still and let the camera focus".into());
    }
    if r.contains("static_scene") {
        return Some("Not enough movement — move your head slightly".into());
    }
    if r.contains("duplicate_pose") {
        return Some("Duplicate pose — turn your head a little".into());
    }
    if r.contains("no_luma") {
        return Some("Camera frames unreadable".into());
    }
    if r.contains("insufficient_templates") {
        return Some("More poses needed — run `hiro enroll` again".into());
    }
    if r.contains("no_templates") || r.contains("no template") {
        return Some("No face enrolled yet".into());
    }
    if r.contains("template_limit") {
        return Some("Template limit reached — remove some templates first".into());
    }
    if r.contains("camera_mismatch") {
        return Some("Camera changed since enrollment".into());
    }
    if r.contains("camera") {
        return Some("Camera unavailable".into());
    }
    if r.contains("no_such_user") || r.contains("no such user") {
        return Some("User not found".into());
    }
    if r.contains("denied") {
        return Some("Access denied".into());
    }
    if r.contains("no_match") {
        return Some("Face not recognized".into());
    }
    if r.is_empty() || r == "error" {
        return Some("Something went wrong".into());
    }
    None
}

/// Should a failure be shown instantly, without faking a scan?
///
/// Rate-limited / locked-out / password-required verdicts are rejected
/// before any scanning happens, so the UI should tell the user immediately
/// instead of flashing a scan that never occurred. Camera failures
/// (`camera_unavailable`, `camera_mismatch`, `no_luma`) are the same: the
/// camera could not be used, so the indicator must say so right away
/// instead of first claiming the user's face is being scanned.
pub fn is_immediate_failure(state: &str, reason: Option<&str>) -> bool {
    if state != "failure" {
        return false;
    }
    let r = reason.unwrap_or("").to_lowercase();
    r.contains("rate_limited")
        || r.contains("rate limited")
        || r.contains("locked_out")
        || r.contains("locked out")
        || r.contains("password_required")
        || r.contains("password required")
        || r.contains("camera")
        || r.contains("no_luma")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_reasons() {
        assert_eq!(
            reason_label(Some("approval_denied")).as_deref(),
            Some("Approval denied")
        );
        assert_eq!(
            reason_label(Some("approval_timeout")).as_deref(),
            Some("Approval timed out — try again")
        );
        assert_eq!(
            reason_label(Some("rate_limited")).as_deref(),
            Some("Rate limited — please wait a moment")
        );
        assert_eq!(
            reason_label(Some("no_face")).as_deref(),
            Some("No face detected")
        );
        assert_eq!(
            reason_label(Some("face_too_small")).as_deref(),
            Some("Face too small — move closer to the camera")
        );
        assert_eq!(
            reason_label(Some("duplicate_pose")).as_deref(),
            Some("Duplicate pose — turn your head a little")
        );
        assert_eq!(
            reason_label(Some("camera_mismatch")).as_deref(),
            Some("Camera changed since enrollment")
        );
        assert_eq!(
            reason_label(Some("no_match")).as_deref(),
            Some("Face not recognized")
        );
        assert_eq!(
            reason_label(Some("liveness_failed")).as_deref(),
            Some("Not enough movement — try again and move your head slightly")
        );
        assert_eq!(
            reason_label(Some("insufficient_templates")).as_deref(),
            Some("More poses needed — run `hiro enroll` again")
        );
    }

    #[test]
    fn unknown_reason_is_none() {
        assert_eq!(reason_label(Some("totally_new_reason")), None);
        assert_eq!(reason_label(None), Some("Something went wrong".into()));
        assert_eq!(reason_label(Some("")), Some("Something went wrong".into()));
    }

    #[test]
    fn immediate_failures() {
        assert!(is_immediate_failure("failure", Some("rate_limited")));
        assert!(is_immediate_failure("failure", Some("password_required")));
        assert!(is_immediate_failure("failure", Some("locked_out")));
        assert!(!is_immediate_failure("failure", Some("no_match")));
        assert!(!is_immediate_failure("success", Some("rate_limited")));
    }

    #[test]
    fn camera_failures_are_immediate() {
        // An unavailable camera fails without ever scanning the user's
        // face, so the indicator must say so at once instead of flashing
        // "Scanning your face…".
        assert!(is_immediate_failure("failure", Some("camera_unavailable")));
        assert!(is_immediate_failure("failure", Some("camera_mismatch")));
        assert!(is_immediate_failure("failure", Some("no_luma")));
        // But a genuine failed scan is not immediate.
        assert!(!is_immediate_failure("failure", Some("no_face")));
        assert!(!is_immediate_failure("success", Some("camera_unavailable")));
    }
}
