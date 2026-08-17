//! Watch-stream client for the HIRO daemon socket.
//!
//! Two roles, mirroring the GNOME Shell extension:
//!
//! * a long-lived `Op::Watch` connection that streams [`StateEvent`]s and
//!   reconnects with a backoff when the daemon is unreachable, and
//! * short-lived `Op::Approve` requests that grant/deny a pending approval.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;

use hiro_core::proto::{Op, Outcome, Request, Response, StateEvent};
use hiro_core::PROTOCOL_VERSION;

/// Wait between reconnect attempts when the daemon socket is unreachable.
pub const RECONNECT_SECS: u64 = 3;
/// Upper bound on an `Op::Approve` round-trip (local socket; normally
/// instant). Keeps the UI from ever freezing on a wedged daemon.
const APPROVE_TIMEOUT_MS: u64 = 2_000;

/// Messages from the reader thread to the GTK main loop.
#[derive(Debug)]
pub enum SocketMsg {
    /// A parsed state broadcast from the daemon.
    Event(Box<StateEvent>),
    /// The watch connection dropped (EOF, error, or initial connect
    /// failure). The UI should hide any stale state; the thread reconnects
    /// on its own and the daemon replays `idle` on reconnect.
    Disconnected,
}

/// Spawn the watch-stream reader thread.
///
/// It connects, sends the `Op::Watch` request, and forwards every parsed
/// [`StateEvent`] to `tx`. On any failure it sends `Disconnected` and retries
/// after [`RECONNECT_SECS`], forever.
pub fn spawn(socket: &Path, tx: Sender<SocketMsg>) {
    let socket = socket.to_path_buf();
    std::thread::spawn(move || loop {
        let outcome = watch_once(&socket, &tx);
        match outcome {
            WatchExit::Eof => log::debug!("watch stream closed by daemon"),
            WatchExit::Err(e) => log::debug!("watch stream failed: {e}"),
        }
        let _ = tx.send(SocketMsg::Disconnected);
        std::thread::sleep(Duration::from_secs(RECONNECT_SECS));
    });
}

enum WatchExit {
    Eof,
    Err(String),
}

impl std::fmt::Debug for WatchExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchExit::Eof => f.write_str("Eof"),
            WatchExit::Err(e) => write!(f, "Err({e})"),
        }
    }
}

fn watch_once(socket: &Path, tx: &Sender<SocketMsg>) -> WatchExit {
    let mut stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(e) => return WatchExit::Err(format!("connect {socket:?}: {e}")),
    };
    // The watch stream blocks between broadcasts (nothing happens while
    // idle); no read timeout on the long-lived connection.
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 0,
        op: Op::Watch,
    };
    let mut line = match serde_json::to_string(&req) {
        Ok(l) => l,
        Err(e) => return WatchExit::Err(format!("serialize watch request: {e}")),
    };
    line.push('\n');
    if let Err(e) = stream.write_all(line.as_bytes()) {
        return WatchExit::Err(format!("write watch request: {e}"));
    }
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => return WatchExit::Err(format!("read: {e}")),
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<StateEvent>(line) {
            Ok(ev) => {
                let _ = tx.send(SocketMsg::Event(Box::new(ev)));
            }
            Err(e) => log::warn!("ignoring unparseable state event: {e}: {line}"),
        }
    }
    WatchExit::Eof
}

/// Grant or deny a pending approval (`Op::Approve`).
///
/// Mirrors the extension's in-session path: `secret` is unset, so the daemon
/// authorizes by SO_PEERCRED (caller uid == target user, or root). Returns
/// whether the daemon accepted the decision.
pub fn approve(socket: &Path, approval_id: u64, user: &str, allow: bool) -> bool {
    let mut stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("approve: connect failed: {e}");
            return false;
        }
    };
    // A wedged daemon must never freeze the UI: bound the round-trip.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(APPROVE_TIMEOUT_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(APPROVE_TIMEOUT_MS)));

    let req = Request {
        v: PROTOCOL_VERSION,
        id: 0,
        op: Op::Approve {
            approval_id,
            user: user.to_string(),
            allow,
            secret: None,
        },
    };
    let mut line = match serde_json::to_string(&req) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("approve: serialize failed: {e}");
            return false;
        }
    };
    line.push('\n');
    if let Err(e) = stream.write_all(line.as_bytes()) {
        log::warn!("approve: write failed: {e}");
        return false;
    }
    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    if let Err(e) = reader.read_line(&mut resp) {
        log::warn!("approve: read failed: {e}");
        return false;
    }
    let resp: Response = match serde_json::from_str(resp.trim_end()) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("approve: bad response: {e}: {resp}");
            return false;
        }
    };
    matches!(resp.outcome, Outcome::Ok { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// A tiny fake daemon that answers `Op::Watch` with an idle replay then
    /// a configurable stream, and `Op::Approve` with a success response.
    struct FakeDaemon {
        socket: PathBuf,
        #[allow(dead_code)]
        thread: std::thread::JoinHandle<()>,
    }

    impl FakeDaemon {
        fn start() -> Self {
            let dir = std::env::temp_dir();
            let socket = dir.join(format!("hiro-ui-test-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&socket);
            let listener = UnixListener::bind(&socket).unwrap();
            let thread = std::thread::spawn(move || {
                for _ in 0..4 {
                    let (mut stream, _) = match listener.accept() {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    let mut line = String::new();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    let resp = if line.contains("\"op\":\"approve\"") {
                        Response::ok(0, hiro_core::proto::ResultValue::Approved)
                    } else {
                        // Idle replay, matching the daemon's reconnect
                        // behaviour.
                        Response::ok(
                            0,
                            hiro_core::proto::ResultValue::Login, // shape matches; only used for JSON
                        )
                    };
                    let mut out = serde_json::to_string(&resp).unwrap();
                    out.push('\n');
                    let _ = stream.write_all(out.as_bytes());
                }
            });
            Self { socket, thread }
        }
    }

    #[test]
    fn approve_roundtrip_accepted() {
        let daemon = FakeDaemon::start();
        assert!(approve(&daemon.socket, 42, "alice", true));
        std::thread::sleep(Duration::from_millis(50));
        let _ = daemon.thread;
    }

    #[test]
    fn approve_unreachable_socket() {
        assert!(!approve(
            Path::new("/nonexistent/hiro.sock"),
            1,
            "bob",
            true
        ));
    }

    #[test]
    fn watch_once_forwards_events() {
        let dir = std::env::temp_dir();
        let socket = dir.join(format!("hiro-ui-watch-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let _ = reader.read_line(&mut line);
            let ev = serde_json::to_string(&StateEvent::scanning("alice")).unwrap();
            let _ = stream.write_all(format!("{ev}\n").as_bytes());
            // Keep the connection open briefly so the reader sees the line.
            std::thread::sleep(Duration::from_millis(100));
        });
        let (tx, rx) = std::sync::mpsc::channel::<SocketMsg>();
        let outcome = watch_once(&socket, &tx);
        assert!(matches!(outcome, WatchExit::Eof), "{outcome:?}");
        if let Ok(ev) = rx.try_recv() {
            match ev {
                SocketMsg::Event(e) => assert_eq!(e.state, "scanning"),
                _ => panic!("expected event"),
            }
        } else {
            panic!("no event received");
        }
        let _ = thread.join();
        let _ = std::fs::remove_file(&socket);
    }
}
