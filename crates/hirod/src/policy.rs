//! Rate limiting, lockout, and caller authorization.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use hiro_core::config::SecurityConfig;

/// The caller identity, from SO_PEERCRED.
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    pub uid: u32,
    pub pid: i32,
}

impl Caller {
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    RateLimited,
    LockedOut,
}

pub struct Policy {
    cfg: SecurityConfig,
    attempts: HashMap<String, VecDeque<Instant>>,
    failures: HashMap<String, (u32, Option<Instant>)>,
    /// Rolling camera-time usage per user: `(acquisition time, hold)`.
    /// Enforced so a single user cannot monopolise the global camera
    /// (blocking every other user's face auth) by chaining requests.
    camera_usage: HashMap<String, VecDeque<CameraUsage>>,
    /// Monotonic tag for camera-budget reservations so a concurrent same-
    /// user request can settle exactly its own reservation on release.
    next_camera_token: u64,
}

/// One camera-time accounting entry. Requests *reserve* their intended hold
/// at acquisition (so the budget is enforced up front, including against
/// queued concurrent requests) and *settle* the reservation to the actual
/// hold on release.
#[derive(Debug, Clone, Copy)]
struct CameraUsage {
    at: Instant,
    held: Duration,
    /// Reservation tag; 0 for settled (actual) usage.
    token: u64,
}

impl Policy {
    pub fn new(cfg: SecurityConfig) -> Self {
        Self {
            cfg,
            attempts: HashMap::new(),
            failures: HashMap::new(),
            camera_usage: HashMap::new(),
            next_camera_token: 0,
        }
    }

    /// Replace the security configuration (on daemon reload).
    pub fn update_cfg(&mut self, cfg: SecurityConfig) {
        self.cfg = cfg;
    }

    /// Check whether a request for `user` is currently allowed.
    pub fn check(&mut self, user: &str) -> PolicyVerdict {
        self.prune(user);
        if let Some((fails, Some(until))) = self.failures.get(user) {
            if *fails >= self.cfg.rate_limit_attempts && Instant::now() < *until {
                return PolicyVerdict::LockedOut;
            }
        }
        let window = Duration::from_secs(self.cfg.rate_limit_window_secs);
        let count = self
            .attempts
            .entry(user.to_string())
            .or_default()
            .iter()
            .filter(|t| t.elapsed() < window)
            .count();
        if count as u32 >= self.cfg.rate_limit_attempts {
            return PolicyVerdict::RateLimited;
        }
        self.attempts
            .entry(user.to_string())
            .or_default()
            .push_back(Instant::now());
        PolicyVerdict::Allow
    }

    pub fn record_failure(&mut self, user: &str) {
        self.prune(user);
        let entry = self.failures.entry(user.to_string()).or_insert((0, None));
        entry.0 += 1;
        if entry.0 >= self.cfg.rate_limit_attempts {
            entry.1 = Some(Instant::now() + Duration::from_secs(self.cfg.lockout_secs));
        }
    }

    pub fn record_success(&mut self, user: &str) {
        self.failures.remove(user);
    }

    /// Reserve camera time for `user` up front so the per-user budget is
    /// enforced *at acquisition*, not just afterwards: a request that passes
    /// the check reserves `min(remaining budget, intended hold)` and that
    /// reservation is what other (including queued concurrent) requests of
    /// the same user see. Returns:
    ///
    /// * `(None, None)` — the budget is disabled (no cap, no reservation);
    /// * `(Some(Duration::ZERO), None)` — no budget left, request refused;
    /// * `(Some(cap), Some(token))` — hold at most `cap`, settle later with
    ///   `token`.
    pub fn camera_budget_reserve(
        &mut self,
        user: &str,
        intended: Duration,
    ) -> (Option<Duration>, Option<u64>) {
        let window = Duration::from_secs(self.cfg.camera_budget_window_secs);
        let max = Duration::from_secs(self.cfg.camera_budget_secs);
        if window.is_zero() || max.is_zero() {
            return (None, None); // budget disabled
        }
        let q = self.camera_usage.entry(user.to_string()).or_default();
        while q.front().is_some_and(|e| e.at.elapsed() >= window) {
            q.pop_front();
        }
        let used: Duration = q.iter().map(|e| e.held).sum();
        if used >= max {
            return (Some(Duration::ZERO), None);
        }
        let cap = (max - used).min(intended);
        self.next_camera_token += 1;
        let token = self.next_camera_token;
        q.push_back(CameraUsage {
            at: Instant::now(),
            held: cap,
            token,
        });
        (Some(cap), Some(token))
    }

    /// Replace the reservation `token` (placed by [`Self::camera_budget_reserve`])
    /// with the actual hold duration, returning any unused allowance to the
    /// user's budget. A reservation that already aged out of the rolling
    /// window is simply gone; the actual hold is recorded fresh.
    pub fn camera_budget_settle(&mut self, user: &str, token: u64, actual: Duration) {
        let window = Duration::from_secs(self.cfg.camera_budget_window_secs);
        let q = self.camera_usage.entry(user.to_string()).or_default();
        while q.front().is_some_and(|e| e.at.elapsed() >= window) {
            q.pop_front();
        }
        if let Some(pos) = q.iter().position(|e| e.token == token) {
            q.remove(pos);
        }
        q.push_back(CameraUsage {
            at: Instant::now(),
            held: actual,
            token: 0,
        });
    }

    /// Whether `user` may acquire the camera right now under the rolling
    /// camera-time budget. A window of zero disables the budget.
    pub fn camera_budget_check(&mut self, user: &str) -> bool {
        let window = Duration::from_secs(self.cfg.camera_budget_window_secs);
        let max = Duration::from_secs(self.cfg.camera_budget_secs);
        if window.is_zero() || max.is_zero() {
            return true; // budget disabled
        }
        let q = self.camera_usage.entry(user.to_string()).or_default();
        while q.front().is_some_and(|e| e.at.elapsed() >= window) {
            q.pop_front();
        }
        let used: Duration = q.iter().map(|e| e.held).sum();
        used < max
    }

    /// Record how long `user` held the camera, against the rolling budget.
    pub fn record_camera_time(&mut self, user: &str, held: Duration) {
        let window = Duration::from_secs(self.cfg.camera_budget_window_secs);
        let q = self.camera_usage.entry(user.to_string()).or_default();
        while q.front().is_some_and(|e| e.at.elapsed() >= window) {
            q.pop_front();
        }
        q.push_back(CameraUsage {
            at: Instant::now(),
            held,
            token: 0,
        });
    }

    fn prune(&mut self, user: &str) {
        let window = Duration::from_secs(self.cfg.rate_limit_window_secs);
        if let Some(queue) = self.attempts.get_mut(user) {
            while queue.front().is_some_and(|t| t.elapsed() > window) {
                queue.pop_front();
            }
        }
        let expired = self
            .failures
            .get(user)
            .and_then(|(_, until)| *until)
            .is_some_and(|t| Instant::now() >= t);
        if expired {
            if let Some((_, until)) = self.failures.get_mut(user) {
                *until = None;
            }
        }
    }
}

/// Authorize a request: root may act on anyone's behalf; otherwise the
/// caller may only act on their own account.
pub fn authorize(caller: Caller, target_uid: Option<u32>) -> bool {
    if caller.is_root() {
        return true;
    }
    match target_uid {
        Some(uid) => caller.uid == uid,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec_cfg() -> SecurityConfig {
        SecurityConfig {
            rate_limit_attempts: 2,
            rate_limit_window_secs: 3600,
            lockout_secs: 60,
            ..SecurityConfig::default()
        }
    }

    #[test]
    fn rate_limit_trips() {
        let mut p = Policy::new(sec_cfg());
        assert_eq!(p.check("alice"), PolicyVerdict::Allow);
        assert_eq!(p.check("alice"), PolicyVerdict::Allow);
        assert_eq!(p.check("alice"), PolicyVerdict::RateLimited);
        assert_eq!(p.check("bob"), PolicyVerdict::Allow);
    }

    #[test]
    fn lockout_after_failures() {
        let mut p = Policy::new(sec_cfg());
        p.record_failure("alice");
        p.record_failure("alice");
        assert_eq!(p.check("alice"), PolicyVerdict::LockedOut);
    }

    #[test]
    fn success_resets_failures() {
        let mut p = Policy::new(sec_cfg());
        p.record_failure("alice");
        p.record_success("alice");
        p.record_failure("alice");
        assert_eq!(p.check("alice"), PolicyVerdict::Allow);
    }

    #[test]
    fn authz_rules() {
        let root = Caller { uid: 0, pid: 1 };
        let me = Caller { uid: 1000, pid: 2 };
        assert!(authorize(root, Some(999)));
        assert!(authorize(root, None));
        assert!(authorize(me, Some(1000)));
        assert!(!authorize(me, Some(1001)));
        assert!(!authorize(me, None));
    }

    #[test]
    fn camera_budget_limits_per_user() {
        let mut p = Policy::new(sec_cfg());
        // 5 * 3s = 15s of camera time fills the 15s / 60s default budget.
        for _ in 0..5 {
            assert!(p.camera_budget_check("alice"));
            p.record_camera_time("alice", Duration::from_secs(3));
        }
        assert!(
            !p.camera_budget_check("alice"),
            "over-budget user must be refused the camera"
        );
        // Other users are unaffected.
        assert!(p.camera_budget_check("bob"));
    }

    #[test]
    fn camera_budget_rolling_window_recovers() {
        let mut cfg = sec_cfg();
        cfg.camera_budget_secs = 1;
        cfg.camera_budget_window_secs = 1;
        let mut p = Policy::new(cfg);
        p.record_camera_time("alice", Duration::from_millis(1100));
        assert!(!p.camera_budget_check("alice"));
        std::thread::sleep(Duration::from_millis(1100));
        // The hold has aged out of the 1s rolling window.
        assert!(p.camera_budget_check("alice"));
    }

    #[test]
    fn camera_budget_disabled_when_zero() {
        let mut cfg = sec_cfg();
        cfg.camera_budget_secs = 0;
        let mut p = Policy::new(cfg);
        for _ in 0..100 {
            assert!(p.camera_budget_check("alice"));
            p.record_camera_time("alice", Duration::from_secs(60));
        }
    }

    #[test]
    fn camera_budget_reservation_caps_hold() {
        let mut p = Policy::new(sec_cfg()); // 15s / 60s default budget
        // A 60s-intended acquire (e.g. enrollment) is capped at the 15s budget.
        let (cap, token) = p.camera_budget_reserve("alice", Duration::from_secs(60));
        assert_eq!(cap, Some(Duration::from_secs(15)));
        let token = token.expect("reservation token");
        // A queued concurrent acquire of the same user sees the reservation
        // and is refused (no budget left).
        let (cap2, _) = p.camera_budget_reserve("alice", Duration::from_secs(60));
        assert_eq!(cap2, Some(Duration::ZERO));
        // Settling returns the unused allowance: 3s actually held of the 15s
        // reservation leaves 12s.
        p.camera_budget_settle("alice", token, Duration::from_secs(3));
        let (cap3, _) = p.camera_budget_reserve("alice", Duration::from_secs(60));
        assert_eq!(cap3, Some(Duration::from_secs(12)));
        // Other users are unaffected by alice's reservation.
        assert!(p.camera_budget_check("bob"));
    }

    #[test]
    fn camera_budget_reserve_refuses_when_exhausted_by_actual_use() {
        let mut p = Policy::new(sec_cfg());
        for _ in 0..5 {
            p.record_camera_time("alice", Duration::from_secs(3));
        }
        let (cap, token) = p.camera_budget_reserve("alice", Duration::from_secs(10));
        assert_eq!(cap, Some(Duration::ZERO));
        assert!(token.is_none());
    }
}
