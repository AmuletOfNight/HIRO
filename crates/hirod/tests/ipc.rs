//! Socket-level integration test: real Unix socket, real dispatch path,
//! mock camera, stub pipeline.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hiro_core::config::Config;
use hiro_core::proto::{Op, Outcome, Request, Response, ResultValue};
use hiro_core::PROTOCOL_VERSION;
use hiro_face::stub::StubPipeline;
use hiro_hw::mock::MockSource;
use hiro_store::Store;
use hiro_tpm::SoftwareKeyManager;
use hirod::state::{Daemon, DaemonOptions, PasswordChecker};

/// Test stand-in for the shadow-password checker: accepts every password.
struct AcceptAllChecker;

impl PasswordChecker for AcceptAllChecker {
    fn check(&self, _user: &str, _password: &str) -> bool {
        true
    }
}

fn current_user() -> String {
    let uid = nix::unistd::geteuid().as_raw();
    let text = std::fs::read_to_string("/etc/passwd").unwrap();
    for line in text.lines() {
        let mut parts = line.split(':');
        let name = parts.next().unwrap().to_string();
        let _ = parts.next();
        if parts.next().unwrap().parse::<u32>().ok() == Some(uid) {
            return name;
        }
    }
    panic!("no current user");
}

fn build_daemon() -> (Arc<Daemon>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hirod.sock");

    let mut cfg = Config::default();
    cfg.recognition.detector = "stub".into();
    cfg.recognition.match_threshold = 0.90;
    cfg.recognition.quorum_frames = 2;
    cfg.camera.max_frames = 20;
    cfg.camera.width = 64;
    cfg.camera.height = 48;
    cfg.device.require_ir = false;
    cfg.daemon.socket_path = socket;
    cfg.keyring.enabled = true;
    cfg.keyring.services = vec!["ipc-keyring".into()];
    // The deterministic mock's landmark motion is marginal across repeated
    // verifies; these tests exercise the IPC flow, not the anti-spoof gate.
    cfg.recognition.enable_liveness = false;
    // The action-approval gate is on by default; these tests exercise the
    // instant-match IPC flow (see approval_flow_over_socket for the gate).
    cfg.approval.enabled = false;

    let daemon = Daemon::build(
        cfg,
        DaemonOptions {
            camera_source: Some(Box::new(MockSource::new(64, 48, vec![]))),
            pipeline: Some(Box::new(StubPipeline::new())),
            key_manager: Some(Box::new(SoftwareKeyManager::from_key([9u8; 32]))),
            store: Some(Store::open_in_memory().unwrap()),
            config_path: None,
            password_checker: Some(Box::new(AcceptAllChecker)),
        },
    )
    .unwrap();
    (daemon, dir)
}

struct Client {
    next_id: u64,
}

impl Client {
    fn new() -> Self {
        Self { next_id: 1 }
    }

    fn call(&mut self, socket: &std::path::Path, op: Op) -> Response {
        let id = self.next_id;
        self.next_id += 1;
        let mut stream = None;
        for _ in 0..100 {
            if let Ok(s) = UnixStream::connect(socket) {
                stream = Some(s);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let mut stream = stream.expect("daemon socket never appeared");
        let req = Request {
            v: PROTOCOL_VERSION,
            id,
            op,
        };
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).unwrap();
        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).unwrap();
        let resp: Response = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(resp.id, id);
        resp
    }
}

/// Record a login for `user`, exactly like `pam_hiro.so`'s session hook
/// does after a successful password login. Arms face auth for the current
/// boot (the after-reboot gate).
///
/// `Op::Login` is honoured only for root callers (the PAM session hook runs
/// as root). When the test process itself runs as root the socket path is
/// exercised end-to-end; otherwise the socket must refuse the non-root
/// caller (proving the gate) and the login is armed directly through the
/// auth layer with a root caller so the rest of the flow stays exercised.
fn arm_login_over_socket(
    client: &mut Client,
    daemon: &Arc<Daemon>,
    socket: &std::path::Path,
    user: &str,
) {
    let resp = client.call(
        socket,
        Op::Login {
            user: user.into(),
            service: "ipc-login".into(),
        },
    );
    if nix::unistd::geteuid().is_root() {
        assert!(
            matches!(
                resp.outcome,
                Outcome::Ok {
                    result: ResultValue::Login
                }
            ),
            "login signal failed: {:?}",
            resp.outcome
        );
    } else {
        assert!(
            matches!(resp.outcome, Outcome::Err { .. }),
            "non-root socket login must be refused (root-only gate): {:?}",
            resp.outcome
        );
        hirod::auth::record_login(
            daemon,
            hirod::policy::Caller { uid: 0, pid: 1 },
            user,
            "ipc-login",
        )
        .unwrap();
    }
}

#[test]
fn full_cycle_over_socket() {
    let (daemon, _dir) = build_daemon();
    let socket = daemon.cfg.read().unwrap().daemon.socket_path.clone();
    let shutdown = Arc::new(AtomicBool::new(false));

    let server_thread = {
        let daemon = daemon.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || hirod::server::serve(daemon, shutdown).unwrap())
    };

    let user = current_user();
    let mut client = Client::new();

    // Ping works.
    let resp = client.call(&socket, Op::Ping);
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Pong { .. }
        }
    ));

    // Simulate the user's password login since boot (PAM session hook),
    // arming face auth for the rest of this boot.
    arm_login_over_socket(&mut client, &daemon, &socket, &user);

    // No templates yet -> fast no_templates verdict.
    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "ipc-test".into(),
            timeout_ms: 2000,
            want_keyring: false,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(!v.matched);
            assert_eq!(v.reason, "no_templates");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Enroll with the face pattern on.
    {
        let mut cam = daemon.camera.lock().unwrap();
        cam.set_mock_face_every(Some(3));
    }
    let resp = client.call(
        &socket,
        Op::Enroll {
            user: user.clone(),
            max_models: 4,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Enroll(r),
        } => {
            assert!(r.added >= 1, "enroll failed: {:?}", r.reports);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Verify matches.
    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "ipc-test".into(),
            timeout_ms: 5000,
            want_keyring: false,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(v.matched, "verify failed: {v:?}");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // List shows templates.
    let resp = client.call(&socket, Op::List { user: user.clone() });
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::List { templates },
        } => {
            assert!(!templates.is_empty());
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Status works.
    let resp = client.call(&socket, Op::Status);
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Status(_)
        }
    ));

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn watch_streams_state_events() {
    let (daemon, _dir) = build_daemon();
    let socket = daemon.cfg.read().unwrap().daemon.socket_path.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let daemon = daemon.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || hirod::server::serve(daemon, shutdown).unwrap())
    };

    // Subscribe before doing anything.
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = UnixStream::connect(&socket) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut stream = stream.expect("socket");
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 99,
        op: Op::Watch,
    };
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Initial idle event.
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert!(
        first.contains("\"idle\""),
        "expected idle event, got {first}"
    );

    // Trigger a verify (fails fast: no templates).
    let user = current_user();
    let mut client = Client::new();
    // Arm face auth for this boot first (as a real password login would).
    arm_login_over_socket(&mut client, &daemon, &socket, &user);
    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "watch-test".into(),
            timeout_ms: 1000,
            want_keyring: false,
        },
    );
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Verify(_)
        }
    ));

    // Expect scanning then failure events.
    let mut saw_scanning = false;
    let mut saw_failure = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline && !(saw_scanning && saw_failure) {
        let mut ev = String::new();
        if reader.read_line(&mut ev).unwrap_or(0) == 0 {
            break;
        }
        if ev.contains("\"scanning\"") {
            saw_scanning = true;
        }
        if ev.contains("\"failure\"") {
            saw_failure = true;
        }
    }
    assert!(saw_scanning, "never saw a scanning event");
    assert!(saw_failure, "never saw a failure event");

    drop(stream);
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn enroll_streams_enrollment_events() {
    let (daemon, _dir) = build_daemon();
    let socket = daemon.cfg.read().unwrap().daemon.socket_path.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let daemon = daemon.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || hirod::server::serve(daemon, shutdown).unwrap())
    };

    // Subscribe before enrolling.
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = UnixStream::connect(&socket) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut stream = stream.expect("socket");
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 99,
        op: Op::Watch,
    };
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Consume the initial idle event.
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();

    // Enroll with the face pattern on.
    {
        let mut cam = daemon.camera.lock().unwrap();
        cam.set_mock_face_every(Some(3));
    }
    let user = current_user();
    let mut client = Client::new();
    arm_login_over_socket(&mut client, &daemon, &socket, &user);
    let resp = client.call(
        &socket,
        Op::Enroll {
            user: user.clone(),
            max_models: 4,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Enroll(r),
        } => assert!(r.added >= 1, "enroll failed: {:?}", r.reports),
        other => panic!("unexpected: {other:?}"),
    }

    // The stream must show an op=enroll scanning event with live progress
    // (accepted/target), live rejection telemetry with a reason code, and a
    // terminal success event carrying the added/rejected counts so the
    // status indicator can report the enrollment result.
    let mut saw_enrolling = false;
    let mut saw_progress = false;
    let mut saw_rejection = false;
    let mut saw_terminal = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline && !saw_terminal {
        let mut ev = String::new();
        if reader.read_line(&mut ev).unwrap_or(0) == 0 {
            break;
        }
        let val: serde_json::Value = serde_json::from_str(&ev).unwrap();
        let state = val["state"].as_str().unwrap_or("");
        let op = val["op"].as_str().unwrap_or("");
        if state == "scanning" && op == "enroll" {
            saw_enrolling = true;
            if val["accepted"].is_number() && val["target"].is_number() {
                saw_progress = true;
            }
            // The mock camera alternates noise and face frames, so frames
            // are rejected; live rejection events must carry the count and a
            // stable reason the UI can show ("move closer", "turn your
            // head", ...).
            if val["rejected"].is_number()
                && val["rejected"].as_u64().unwrap_or(0) > 0
                && val["reason"].is_string()
            {
                saw_rejection = true;
            }
        }
        if state == "success" && op == "enroll" {
            saw_terminal = true;
            assert!(
                val["accepted"].as_u64().unwrap_or(0) >= 1,
                "terminal enroll event missing added count: {ev}"
            );
            assert!(
                val["rejected"].is_number(),
                "terminal enroll event missing rejected count: {ev}"
            );
        }
    }
    assert!(saw_enrolling, "never saw an op=enroll scanning event");
    assert!(saw_progress, "never saw enroll progress fields");
    assert!(saw_rejection, "never saw a live enrollment rejection event");
    assert!(saw_terminal, "never saw a terminal enroll success event");

    drop(stream);
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn reaper_exits_on_shutdown() {
    let (daemon, _dir) = build_daemon();
    let shutdown = Arc::new(AtomicBool::new(false));
    let reaper = hirod::camera::spawn_reaper(daemon.camera.clone(), shutdown.clone());

    // Let the reaper start, then ask it to stop.
    std::thread::sleep(std::time::Duration::from_millis(50));
    shutdown.store(true, Ordering::Relaxed);

    // Must exit well within one poll interval.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !reaper.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        reaper.is_finished(),
        "reaper thread did not exit after shutdown flag was set"
    );
    reaper.join().unwrap();
}

#[test]
fn keyring_flow_over_socket() {
    let (daemon, dir) = build_daemon();
    let socket = daemon.cfg.read().unwrap().daemon.socket_path.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let daemon = daemon.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || hirod::server::serve(daemon, shutdown).unwrap())
    };

    let user = current_user();
    let mut client = Client::new();

    // A real login would have armed face auth for this boot already.
    arm_login_over_socket(&mut client, &daemon, &socket, &user);

    // Not armed yet.
    let resp = client.call(&socket, Op::KeyringStatus { user: user.clone() });
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::KeyringStatus { enabled, stored },
        } => {
            assert!(enabled);
            assert!(!stored);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Store the sealed password (the stub checker accepts it).
    let resp = client.call(
        &socket,
        Op::KeyringSet {
            user: user.clone(),
            password: "login-password".into(),
        },
    );
    eprintln!("KEYSET RESP: {:?}", resp.outcome);
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::KeyringSet { stored: true }
        }
    ));

    // Now armed.
    let resp = client.call(&socket, Op::KeyringStatus { user: user.clone() });
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::KeyringStatus { enabled, stored },
        } => {
            assert!(enabled);
            assert!(stored);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Enroll the face, then verify with want_keyring on the listed service:
    // the sealed password must come back over the socket.
    {
        let mut cam = daemon.camera.lock().unwrap();
        cam.set_mock_face_every(Some(3));
    }
    let resp = client.call(
        &socket,
        Op::Enroll {
            user: user.clone(),
            max_models: 4,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Enroll(r),
        } => assert!(r.added >= 1, "enroll failed: {:?}", r.reports),
        other => panic!("unexpected: {other:?}"),
    }

    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "ipc-keyring".into(),
            timeout_ms: 5000,
            want_keyring: true,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(v.matched, "verify failed: {v:?}");
            // The sealed login password is released only to root callers
            // (greeter/login stacks). A same-uid process — even one asking
            // on a listed service — must never receive it: that is the
            // silent-harvesting hole this hardening closes.
            if nix::unistd::geteuid().is_root() {
                assert_eq!(
                    v.keyring_password.as_deref(),
                    Some("login-password"),
                    "root callers should receive the sealed password on a listed service"
                );
            } else {
                assert!(
                    v.keyring_password.is_none(),
                    "same-uid callers must never receive the login password"
                );
            }
        }
        other => panic!("unexpected: {other:?}"),
    }

    // A verify on a service outside the list must not release it.
    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "sudo".into(),
            timeout_ms: 5000,
            want_keyring: true,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(v.matched);
            assert!(v.keyring_password.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Clear it.
    let resp = client.call(&socket, Op::KeyringClear { user: user.clone() });
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::KeyringCleared { removed: true }
        }
    ));
    let resp = client.call(&socket, Op::KeyringStatus { user: user.clone() });
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::KeyringStatus { enabled, stored },
        } => {
            assert!(enabled);
            assert!(!stored);
        }
        other => panic!("unexpected: {other:?}"),
    }

    let _ = dir;
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn login_gate_blocks_verify_until_login_over_socket() {
    let (daemon, dir) = build_daemon();
    let socket = daemon.cfg.read().unwrap().daemon.socket_path.clone();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let daemon = daemon.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || hirod::server::serve(daemon, shutdown).unwrap())
    };

    let user = current_user();
    let mut client = Client::new();

    // Before any login since boot, verify is refused without scanning.
    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "ipc-gate".into(),
            timeout_ms: 1000,
            want_keyring: false,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(!v.matched);
            assert!(v.camera_ok, "gate must not blame the camera");
            assert_eq!(v.reason, "password_required");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Enrollment is refused too.
    let resp = client.call(
        &socket,
        Op::Enroll {
            user: user.clone(),
            max_models: 4,
        },
    );
    assert!(
        matches!(resp.outcome, Outcome::Err { .. }),
        "enroll should be gated: {:?}",
        resp.outcome
    );

    // After a login signal (as the PAM session hook sends), face auth arms.
    arm_login_over_socket(&mut client, &daemon, &socket, &user);
    let resp = client.call(
        &socket,
        Op::Verify {
            user: user.clone(),
            service: "ipc-gate".into(),
            timeout_ms: 1000,
            want_keyring: false,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(!v.matched, "no templates yet");
            assert_eq!(v.reason, "no_templates");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // An unauthorized caller cannot arm another user. (Skipped when the
    // test itself runs as root, which may arm anyone.)
    if !nix::unistd::geteuid().is_root() {
        let resp = client.call(
            &socket,
            Op::Login {
                user: "root".into(),
                service: "ipc-gate".into(),
            },
        );
        assert!(matches!(resp.outcome, Outcome::Err { .. }));
    }

    let _ = dir;
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    server_thread.join().unwrap();
}

/// A daemon (with a real server thread) running with the approval gate
/// enabled and one enrolled face, exactly as the action-approval feature
/// expects: non-login services park after a confident match until an
/// Allow/Disallow decision arrives.
struct ApprovalEnv {
    daemon: Arc<Daemon>,
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    shutdown: Arc<AtomicBool>,
    server_thread: std::thread::JoinHandle<()>,
    user: String,
}

fn start_approval_env(approval_timeout_ms: u64) -> ApprovalEnv {
    let (daemon, dir) = build_daemon();
    let socket = daemon.cfg.read().unwrap().daemon.socket_path.clone();
    {
        let mut cfg = daemon.cfg.write().unwrap();
        cfg.approval.enabled = true;
        cfg.approval.timeout_ms = approval_timeout_ms;
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_thread = {
        let daemon = daemon.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || hirod::server::serve(daemon, shutdown).unwrap())
    };

    let user = current_user();
    let mut client = Client::new();
    arm_login_over_socket(&mut client, &daemon, &socket, &user);
    {
        let mut cam = daemon.camera.lock().unwrap();
        cam.set_mock_face_every(Some(3));
    }
    let resp = client.call(
        &socket,
        Op::Enroll {
            user: user.clone(),
            max_models: 4,
        },
    );
    match resp.outcome {
        Outcome::Ok {
            result: ResultValue::Enroll(r),
        } => assert!(r.added >= 1, "enroll failed: {:?}", r.reports),
        other => panic!("unexpected: {other:?}"),
    }

    ApprovalEnv {
        daemon,
        _dir: dir,
        socket,
        shutdown,
        server_thread,
        user,
    }
}

/// Open a `Op::Watch` subscription, consuming the initial idle event.
fn open_watch(socket: &std::path::Path) -> (UnixStream, BufReader<UnixStream>) {
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = UnixStream::connect(socket) {
            stream = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut stream = stream.expect("socket");
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 99,
        op: Op::Watch,
    };
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    // Consume the initial idle event.
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    (stream, reader)
}

/// Read state events until the `approval_pending` event arrives, returning
/// it so the caller can read the `approval_id` and `service`.
fn wait_for_approval(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let mut ev = String::new();
        if reader.read_line(&mut ev).unwrap_or(0) == 0 {
            break;
        }
        let val: serde_json::Value = serde_json::from_str(&ev).unwrap();
        if val["state"].as_str() == Some("approval_pending") {
            return val;
        }
    }
    panic!("never saw an approval_pending event");
}

/// Read state events until the daemon reports the user stepped away
/// (`approval_pending` with `user_present: false`).
fn wait_for_user_absent(reader: &mut BufReader<UnixStream>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let mut ev = String::new();
        if reader.read_line(&mut ev).unwrap_or(0) == 0 {
            break;
        }
        let val: serde_json::Value = serde_json::from_str(&ev).unwrap();
        if val["state"].as_str() == Some("approval_pending")
            && val["user_present"].as_bool() == Some(false)
        {
            return;
        }
    }
    panic!("never saw the user step away (user_present: false)");
}

/// Fire a `sudo`-style verify in a background thread: the daemon parks it
/// until the approval is decided, so the caller can drive the UI.
fn verify_in_background(
    socket: &std::path::Path,
    user: &str,
    service: &str,
) -> std::thread::JoinHandle<Response> {
    let socket = socket.to_path_buf();
    let user = user.to_string();
    let service = service.to_string();
    std::thread::spawn(move || {
        let mut c = Client::new();
        c.call(
            &socket,
            Op::Verify {
                user,
                service,
                timeout_ms: 5000,
                want_keyring: false,
            },
        )
    })
}

#[test]
fn approval_grant_and_deny_over_socket() {
    let env = start_approval_env(5000);
    let socket = env.socket.clone();
    let user = env.user.clone();

    // Grant: the UI reads approval_pending, clicks Allow, the parked
    // verify completes as a match.
    let (stream, mut reader) = open_watch(&socket);
    let vt = verify_in_background(&socket, &user, "ipc-sudo");
    let ev = wait_for_approval(&mut reader);
    assert_eq!(ev["service"].as_str(), Some("ipc-sudo"));
    assert_eq!(ev["user"].as_str(), Some(user.as_str()));
    let approval_id = ev["approval_id"].as_u64().expect("approval_id");
    let mut decider = Client::new();
    let resp = decider.call(
        &socket,
        Op::Approve {
            approval_id,
            user: user.clone(),
            allow: true,
            secret: None,
        },
    );
    assert!(
        matches!(
            resp.outcome,
            Outcome::Ok {
                result: ResultValue::Approved
            }
        ),
        "approve failed: {:?}",
        resp.outcome
    );
    match vt.join().unwrap().outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => assert!(v.matched, "grant should match: {v:?}"),
        other => panic!("unexpected: {other:?}"),
    }
    drop(stream);

    // Deny: a fresh request, clicked Deny -> clean non-match.
    let (stream, mut reader) = open_watch(&socket);
    let vt = verify_in_background(&socket, &user, "ipc-sudo");
    let ev = wait_for_approval(&mut reader);
    let approval_id = ev["approval_id"].as_u64().expect("approval_id");
    let resp = decider.call(
        &socket,
        Op::Approve {
            approval_id,
            user: user.clone(),
            allow: false,
            secret: None,
        },
    );
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Approved
        }
    ));
    match vt.join().unwrap().outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(!v.matched, "denial must fail: {v:?}");
            assert_eq!(v.reason, "approval_denied");
        }
        other => panic!("unexpected: {other:?}"),
    }
    drop(stream);

    env.shutdown
        .store(true, std::sync::atomic::Ordering::Relaxed);
    env.server_thread.join().unwrap();
}

#[test]
fn approval_times_out_over_socket() {
    let env = start_approval_env(250);
    let socket = env.socket.clone();
    let user = env.user.clone();

    let (stream, mut reader) = open_watch(&socket);
    let vt = verify_in_background(&socket, &user, "ipc-sudo");
    let _ = wait_for_approval(&mut reader);
    // Never decide: the daemon's window expires on its own.
    match vt.join().unwrap().outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(!v.matched, "undecided approval must fail: {v:?}");
            assert_eq!(v.reason, "approval_timeout");
        }
        other => panic!("unexpected: {other:?}"),
    }
    drop(stream);

    env.shutdown
        .store(true, std::sync::atomic::Ordering::Relaxed);
    env.server_thread.join().unwrap();
}

#[test]
fn approval_walks_away_then_times_out_over_socket() {
    let env = start_approval_env(500);
    // The mock emits a face every 3rd frame, so right after the match the
    // camera shows two consecutive noise frames. With absent_frames = 2
    // the daemon detects the user stepping away almost immediately: the
    // buttons must disappear (user_present: false) but the request must
    // keep waiting until the window expires.
    env.daemon.cfg.write().unwrap().approval.absent_frames = 2;
    let socket = env.socket.clone();
    let user = env.user.clone();

    let (stream, mut reader) = open_watch(&socket);
    let vt = verify_in_background(&socket, &user, "ipc-sudo");
    let ev = wait_for_approval(&mut reader);
    assert_eq!(ev["user_present"].as_bool(), Some(true));
    wait_for_user_absent(&mut reader);
    match vt.join().unwrap().outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => {
            assert!(!v.matched, "walk-away must run out the window: {v:?}");
            assert_eq!(v.reason, "approval_timeout");
        }
        other => panic!("unexpected: {other:?}"),
    }
    drop(stream);

    env.shutdown
        .store(true, std::sync::atomic::Ordering::Relaxed);
    env.server_thread.join().unwrap();
}

#[test]
fn approve_requires_authorization_over_socket() {
    let env = start_approval_env(5000);
    let socket = env.socket.clone();
    let user = env.user.clone();

    let (stream, mut reader) = open_watch(&socket);
    let vt = verify_in_background(&socket, &user, "ipc-sudo");
    let ev = wait_for_approval(&mut reader);
    let approval_id = ev["approval_id"].as_u64().expect("approval_id");

    // An unknown approval id is rejected.
    let mut decider = Client::new();
    let resp = decider.call(
        &socket,
        Op::Approve {
            approval_id: approval_id + 10_000,
            user: user.clone(),
            allow: true,
            secret: None,
        },
    );
    assert!(matches!(resp.outcome, Outcome::Err { .. }));

    // A wrong user name is rejected even though the caller is the daemon
    // socket owner (authorization is against the pending request's user).
    let resp = decider.call(
        &socket,
        Op::Approve {
            approval_id,
            user: "root".into(),
            allow: true,
            secret: None,
        },
    );
    assert!(matches!(resp.outcome, Outcome::Err { .. }));

    // The right user works, and the parked verify completes.
    let resp = decider.call(
        &socket,
        Op::Approve {
            approval_id,
            user: user.clone(),
            allow: true,
            secret: None,
        },
    );
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Approved
        }
    ));
    match vt.join().unwrap().outcome {
        Outcome::Ok {
            result: ResultValue::Verify(v),
        } => assert!(v.matched, "grant should match: {v:?}"),
        other => panic!("unexpected: {other:?}"),
    }
    drop(stream);

    env.shutdown
        .store(true, std::sync::atomic::Ordering::Relaxed);
    env.server_thread.join().unwrap();
}

/// H-3: with `approval.secure_desktop`, a decision may only come from the
/// root-owned dialog that was given the per-approval secret. A same-uid
/// caller is rejected even if it somehow knew the secret; a root caller is
/// rejected without it.
#[test]
fn secure_approval_requires_root_and_secret() {
    let env = start_approval_env(800);
    {
        let mut cfg = env.daemon.cfg.write().unwrap();
        cfg.approval.secure_desktop = true;
        // Point the dialog spawn at a path that cannot exist so the test
        // never actually switches VTs or launches a helper.
        cfg.approval.secure_dialog = "/nonexistent/hiro-approve".into();
    }
    let socket = env.socket.clone();
    let user = env.user.clone();

    let (stream, mut reader) = open_watch(&socket);
    let vt = verify_in_background(&socket, &user, "ipc-sudo");
    let ev = wait_for_approval(&mut reader);
    let approval_id = ev["approval_id"].as_u64().expect("approval_id");
    assert_eq!(ev["secure"].as_bool(), Some(true));

    // Read the per-approval secret from the daemon's own state. A real
    // same-uid attacker cannot read the root dialog's argv; the test can
    // because it holds the daemon handle.
    let secret = {
        let approvals = env.daemon.approvals.lock().unwrap();
        approvals
            .get(&approval_id)
            .expect("pending approval")
            .secret
            .clone()
            .expect("secure approval must carry a secret")
    };

    let mut decider = Client::new();
    if nix::unistd::geteuid().is_root() {
        // Root + correct secret: the decision is accepted.
        let resp = decider.call(
            &socket,
            Op::Approve {
                approval_id,
                user: user.clone(),
                allow: true,
                secret: Some(secret),
            },
        );
        assert!(
            matches!(resp.outcome, Outcome::Ok { .. }),
            "root + secret should approve: {:?}",
            resp.outcome
        );
        // Root without the secret is rejected.
        let resp = decider.call(
            &socket,
            Op::Approve {
                approval_id,
                user: user.clone(),
                allow: true,
                secret: None,
            },
        );
        assert!(matches!(resp.outcome, Outcome::Err { .. }));
    } else {
        // A same-uid (non-root) caller is rejected even with the secret.
        let resp = decider.call(
            &socket,
            Op::Approve {
                approval_id,
                user: user.clone(),
                allow: true,
                secret: Some(secret),
            },
        );
        assert!(
            matches!(resp.outcome, Outcome::Err { .. }),
            "non-root callers must never decide secure approvals: {:?}",
            resp.outcome
        );
        // And without it.
        let resp = decider.call(
            &socket,
            Op::Approve {
                approval_id,
                user: user.clone(),
                allow: true,
                secret: None,
            },
        );
        assert!(matches!(resp.outcome, Outcome::Err { .. }));
    }

    // Whether or not the decision landed, the parked request resolves
    // (immediately, or via the 800 ms window expiring).
    let _ = vt.join().unwrap();

    drop(stream);
    env.shutdown
        .store(true, std::sync::atomic::Ordering::Relaxed);
    env.server_thread.join().unwrap();
}
