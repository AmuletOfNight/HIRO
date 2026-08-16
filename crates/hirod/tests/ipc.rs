//! Socket-level integration test: real Unix socket, real dispatch path,
//! mock camera, stub pipeline.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use hiro_core::config::Config;
use hiro_core::proto::{Op, Outcome, Request, Response, ResultValue};
use hiro_core::PROTOCOL_VERSION;
use hiro_face::stub::StubPipeline;
use hiro_hw::mock::MockSource;
use hiro_store::Store;
use hiro_tpm::SoftwareKeyManager;
use hirod::state::{Daemon, DaemonOptions};

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

    let daemon = Daemon::build(
        cfg,
        DaemonOptions {
            camera_source: Some(Box::new(MockSource::new(64, 48, vec![]))),
            pipeline: Some(Box::new(StubPipeline::new())),
            key_manager: Some(Box::new(SoftwareKeyManager::from_key([9u8; 32]))),
            store: Some(Store::open_in_memory().unwrap()),
            config_path: None,
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
