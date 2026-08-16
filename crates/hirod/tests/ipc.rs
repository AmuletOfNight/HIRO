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

#[test]
fn full_cycle_over_socket() {
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

    // Ping works.
    let resp = client.call(&socket, Op::Ping);
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Pong { .. }
        }
    ));

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

    // Snapshot writes a PGM.
    let shot = dir.path().join("shot.pgm");
    let resp = client.call(
        &socket,
        Op::Snapshot {
            path: shot.display().to_string(),
        },
    );
    assert!(matches!(
        resp.outcome,
        Outcome::Ok {
            result: ResultValue::Snapshot { .. }
        }
    ));
    let data = std::fs::read_to_string(&shot).unwrap();
    assert!(
        data.starts_with("P5\n"),
        "expected PGM header, got {data:?}"
    );

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
    // and a terminal success event carrying the added/rejected counts so
    // the status indicator can report the enrollment result.
    let mut saw_enrolling = false;
    let mut saw_progress = false;
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
            assert_eq!(
                v.keyring_password.as_deref(),
                Some("login-password"),
                "sealed password should be released on a match"
            );
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
