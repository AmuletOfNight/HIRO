//! Unix-socket IPC server: framing, peer-credential authz context,
//! request dispatch.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hiro_core::proto::{
    Op, Request, Response, ResultValue, StatusResult, TemplateInfo, VerifyResult,
};
use hiro_core::{PROTOCOL_VERSION, VERSION};

use crate::audit::audit;
use crate::auth;
use crate::policy::{authorize, Caller};
use crate::state::SharedDaemon;

/// Serve requests on the configured socket until `shutdown` is set.
pub fn serve(daemon: SharedDaemon, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    let path = daemon
        .cfg
        .read()
        .map_err(|_| "cfg lock poisoned".to_string())?
        .daemon
        .socket_path
        .clone();

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::remove_file(&path);

    let listener =
        UnixListener::bind(&path).map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot set socket nonblocking: {e}"))?;
    log::info!("hirod listening on {}", path.display());

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let daemon = daemon.clone();
                std::thread::spawn(move || {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_conn(&daemon, stream);
                    }));
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!("accept failed: {e}"));
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn peer_credentials(stream: &UnixStream) -> Option<Caller> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds = getsockopt(stream, PeerCredentials).ok()?;
    Some(Caller {
        uid: creds.uid(),
        pid: creds.pid(),
    })
}

/// Stream authentication state events to a `Op::Watch` subscriber until
/// the connection closes.
fn handle_watch(daemon: &SharedDaemon, writer: &mut UnixStream) {
    use std::io::Write;
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    {
        let mut watchers = match daemon.watchers.lock() {
            Ok(w) => w,
            Err(_) => return,
        };
        watchers.push(tx);
    }
    if let Ok(json) = serde_json::to_string(&hiro_core::proto::StateEvent::idle()) {
        let mut line = json;
        line.push('\n');
        let _ = writer.write_all(line.as_bytes());
    }
    while let Ok(line) = rx.recv() {
        if writer.write_all(line.as_bytes()).is_err() {
            break;
        }
        let _ = writer.flush();
    }
    // Sender is dropped here; broadcast_state prunes dead senders.
}

fn handle_conn(daemon: &SharedDaemon, stream: UnixStream) {
    let caller = match peer_credentials(&stream) {
        Some(c) => c,
        None => {
            log::warn!("connection without peer credentials; rejecting");
            return;
        }
    };
    let reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) if matches!(req.op, Op::Watch) => {
                handle_watch(daemon, &mut writer);
                break;
            }
            Ok(req) if req.v == PROTOCOL_VERSION => dispatch(daemon, caller, req),
            Ok(_) => Response::err(0, "protocol version mismatch"),
            Err(e) => Response::err(0, format!("bad request: {e}")),
        };
        let mut out = serde_json::to_string(&response).expect("response serializes");
        out.push('\n');
        if writer.write_all(out.as_bytes()).is_err() {
            break;
        }
    }
}

fn dispatch(daemon: &SharedDaemon, caller: Caller, req: Request) -> Response {
    let id = req.id;
    match req.op {
        Op::Ping => Response::ok(
            id,
            ResultValue::Pong {
                daemon: VERSION.into(),
            },
        ),
        Op::Verify {
            user,
            service,
            timeout_ms,
        } => match auth::verify(daemon, caller, &user, &service, timeout_ms) {
            Ok(result) => Response::ok(id, ResultValue::Verify(result)),
            Err(e) => Response::ok(id, ResultValue::Verify(verdict_from_error(&user, &e))),
        },
        Op::Enroll { user, max_models } => match auth::enroll(daemon, caller, &user, max_models) {
            Ok(result) => Response::ok(id, ResultValue::Enroll(result)),
            Err(e) => Response::err(id, e),
        },
        Op::Status => match status(daemon) {
            Ok(s) => Response::ok(id, ResultValue::Status(s)),
            Err(e) => Response::err(id, e),
        },
        Op::List { user } => match list(daemon, caller, &user) {
            Ok(templates) => Response::ok(id, ResultValue::List { templates }),
            Err(e) => Response::err(id, e),
        },
        Op::Remove { user, template_id } => match remove(daemon, caller, &user, template_id) {
            Ok(()) => Response::ok(id, ResultValue::Removed { id: template_id }),
            Err(e) => Response::err(id, e),
        },
        Op::Clear { user } => match clear(daemon, caller, &user) {
            Ok(count) => Response::ok(id, ResultValue::Cleared { count }),
            Err(e) => Response::err(id, e),
        },
        Op::Snapshot { path } => match snapshot(daemon, &path) {
            Ok(()) => Response::ok(id, ResultValue::Snapshot { path }),
            Err(e) => Response::err(id, e),
        },
        Op::Reload => match reload(daemon) {
            Ok(()) => Response::ok(id, ResultValue::Reloaded),
            Err(e) => Response::err(id, e),
        },
        Op::Prewarm => match prewarm(daemon) {
            Ok(()) => Response::ok(id, ResultValue::Prewarmed),
            Err(e) => Response::err(id, e),
        },
        Op::Watch => Response::err(id, "watch is a streaming op"),
    }
}

fn verdict_from_error(user: &str, e: &str) -> VerifyResult {
    let (reason, camera_ok) = if e.contains("rate limited") {
        ("rate_limited", true)
    } else if e.contains("locked out") {
        ("locked_out", true)
    } else if e.contains("no such user") {
        ("no_such_user", true)
    } else if e.contains("denied") {
        ("denied", true)
    } else if e.contains("camera") {
        ("camera_unavailable", false)
    } else {
        ("error", true)
    };
    VerifyResult {
        matched: false,
        user: user.into(),
        score: None,
        template_id: None,
        frames_analyzed: 0,
        liveness_ok: false,
        camera_ok,
        elapsed_ms: 0,
        reason: reason.into(),
    }
}

fn uid_of(user: &str) -> Result<u32, String> {
    crate::lookup::uid_of(user).ok_or_else(|| format!("no such user: {user}"))
}

fn require_authorized(caller: Caller, user: &str) -> Result<(), String> {
    let uid = uid_of(user)?;
    if authorize(caller, Some(uid)) {
        Ok(())
    } else {
        Err(format!("caller uid {} may not act for {user}", caller.uid))
    }
}

fn status(daemon: &SharedDaemon) -> Result<StatusResult, String> {
    let camera = daemon
        .camera
        .lock()
        .map_err(|_| "camera lock poisoned".to_string())?;
    let pipeline = daemon
        .pipeline
        .read()
        .map_err(|_| "pipeline lock poisoned".to_string())?;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    Ok(StatusResult {
        version: VERSION.into(),
        camera: camera.camera_path(),
        driver: camera.driver(),
        ir_detected: camera.is_ir_candidate(),
        emitter_active: Some(camera.streaming()),
        models_loaded: pipeline.loaded(),
        pipeline: pipeline.name().into(),
        templates: store.total_templates().map_err(|e| e.to_string())?,
        tpm_available: Some(daemon.km.tpm_available()),
        uptime_secs: daemon.started_at.elapsed().as_secs(),
    })
}

fn list(daemon: &SharedDaemon, caller: Caller, user: &str) -> Result<Vec<TemplateInfo>, String> {
    require_authorized(caller, user)?;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    let rows = store.list_templates(user).map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| TemplateInfo {
            id: r.id,
            created_at: r.created_at,
            quality: r.quality,
            device: None,
        })
        .collect())
}

fn remove(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    template_id: i64,
) -> Result<(), String> {
    require_authorized(caller, user)?;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    store
        .remove_template(user, template_id)
        .map_err(|e| e.to_string())?;
    audit(
        &store,
        Some(user),
        "remove_template",
        &format!("id={template_id}"),
    );
    Ok(())
}

fn clear(daemon: &SharedDaemon, caller: Caller, user: &str) -> Result<usize, String> {
    require_authorized(caller, user)?;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    let count = store.clear_templates(user).map_err(|e| e.to_string())?;
    audit(
        &store,
        Some(user),
        "clear_templates",
        &format!("count={count}"),
    );
    Ok(count)
}

fn snapshot(daemon: &SharedDaemon, path: &str) -> Result<(), String> {
    let mut camera = daemon
        .camera
        .lock()
        .map_err(|_| "camera lock poisoned".to_string())?;
    camera.acquire().map_err(|e| e.to_string())?;
    let frame = camera
        .next_frame(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?
        .ok_or("camera timed out")?;
    let gray = frame.to_gray().ok_or_else(|| {
        format!(
            "frame format has no luma ({} bytes, {}x{}, {:?})",
            frame.data.len(),
            frame.width,
            frame.height,
            frame.format
        )
    })?;
    let mut out = format!("P5\n{} {}\n255\n", frame.width, frame.height).into_bytes();
    out.extend_from_slice(&gray);
    std::fs::write(path, out).map_err(|e| format!("cannot write {path}: {e}"))?;
    camera.release();
    {
        let store = daemon
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        audit(&store, None, "snapshot", path);
    }
    Ok(())
}

fn reload(daemon: &SharedDaemon) -> Result<(), String> {
    let cfg_path = daemon
        .config_path
        .clone()
        .unwrap_or_else(default_config_path);
    daemon.reload(&cfg_path)
}

fn prewarm(daemon: &SharedDaemon) -> Result<(), String> {
    let mut camera = daemon
        .camera
        .lock()
        .map_err(|_| "camera lock poisoned".to_string())?;
    camera.acquire().map_err(|e| e.to_string())?;
    camera.release();
    Ok(())
}

fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/hiro/config.toml")
}
