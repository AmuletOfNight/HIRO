//! Unix-socket IPC server: framing, peer-credential authz context,
//! request dispatch.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use hiro_core::proto::{
    Op, Request, Response, ResultValue, StatusResult, TemplateInfo, VerifyResult,
};
use hiro_core::{PROTOCOL_VERSION, VERSION};

use crate::audit::audit;
use crate::auth::{self, AuthError};
use crate::policy::{authorize, Caller};
use crate::state::SharedDaemon;

/// Maximum concurrent client connections. The daemon spawns a thread per
/// connection, so this bounds thread/fd exhaustion by local callers (the
/// socket is world-connectable by design).
pub const MAX_CONNECTIONS: usize = 32;
/// Per-uid cap on concurrent connections. Without it, a single local
/// account could pin every server slot with idle `Op::Watch` streams (which
/// live for as long as the subscriber reads) and permanently disable face
/// authentication for everyone — new PAM clients would all receive
/// "server busy" and fall back to passwords. With the cap, one account can
/// hold at most a handful of slots and the rest stay available for other
/// users.
pub const MAX_CONNECTIONS_PER_UID: usize = 8;
/// Hard caps on `Op::Watch` subscriptions: each one occupies a connection
/// slot and fans out every broadcast, so bound them globally and per uid.
pub const MAX_WATCHERS: usize = 16;
pub const MAX_WATCHERS_PER_UID: usize = 4;
/// Idle read timeout on a client connection: a connection that sends
/// nothing for this long is closed instead of pinning a thread forever.
const CONN_IDLE_TIMEOUT_SECS: i64 = 30;

/// Guard that releases the global and per-uid connection-slot counters when
/// the handler thread exits (normally or via a panic).
struct ConnSlot {
    active: Arc<AtomicUsize>,
    by_uid: Arc<std::sync::Mutex<std::collections::HashMap<u32, usize>>>,
    uid: u32,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut map) = self.by_uid.lock() {
            if let Some(c) = map.get_mut(&self.uid) {
                *c -= 1;
                if *c == 0 {
                    map.remove(&self.uid);
                }
            }
        }
    }
}

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

    let active = Arc::new(AtomicUsize::new(0));
    let by_uid: Arc<std::sync::Mutex<std::collections::HashMap<u32, usize>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Resolve the caller identity before spending a slot so the
                // per-uid cap can be enforced. The same SO_PEERCRED value is
                // used for authorization inside handle_conn.
                let uid = peer_credentials(&stream).map(|c| c.uid);
                let admitted = match uid {
                    Some(u) => match by_uid.lock() {
                        Ok(mut map) => {
                            let per_uid = map.get(&u).copied().unwrap_or(0);
                            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS
                                || per_uid >= MAX_CONNECTIONS_PER_UID
                            {
                                false
                            } else {
                                active.fetch_add(1, Ordering::Relaxed);
                                *map.entry(u).or_insert(0) += 1;
                                true
                            }
                        }
                        Err(_) => {
                            log::warn!("rejecting connection: conn table poisoned");
                            false
                        }
                    },
                    None => {
                        // No peer credentials (not expected on AF_UNIX):
                        // enforce only the global cap.
                        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                            false
                        } else {
                            active.fetch_add(1, Ordering::Relaxed);
                            true
                        }
                    }
                };
                if !admitted {
                    log::warn!("rejecting connection: server busy (max {MAX_CONNECTIONS} connections)");
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.write_all(
                        serde_json::to_string(&Response::err(0, "server busy"))
                            .map(|mut s| {
                                s.push('\n');
                                s
                            })
                            .unwrap_or_default()
                            .as_bytes(),
                    );
                    continue;
                }
                let slot = ConnSlot {
                    active: active.clone(),
                    by_uid: by_uid.clone(),
                    uid: uid.unwrap_or(u32::MAX),
                };
                let daemon = daemon.clone();
                std::thread::spawn(move || {
                    let _slot = slot;
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

/// Set an idle read timeout on a connected stream so a silent client can
/// never pin a handler thread forever.
fn set_read_timeout(stream: &UnixStream, secs: i64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Timeval {
        tv_sec: libc::time_t,
        tv_usec: libc::suseconds_t,
    }
    let tv = Timeval {
        tv_sec: secs as libc::time_t,
        tv_usec: 0,
    };
    // SAFETY: tv is a valid timeval; the fd is a valid socket descriptor.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const Timeval).cast(),
            std::mem::size_of::<Timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Whether the peer process is still connected (data pending, or alive and
/// idle). Uses a non-blocking `recv(MSG_PEEK|MSG_DONTWAIT)` so it never
/// blocks; returns false only on EOF or a hard error.
fn peer_alive(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut probe = [0u8; 1];
    // SAFETY: probe is valid writable storage of one byte; MSG_PEEK does not
    // consume data and MSG_DONTWAIT never blocks.
    let n = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            probe.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n > 0 {
        return true;
    }
    if n == 0 {
        return false; // EOF: the peer closed its end
    }
    // n < 0: EAGAIN/EWOULDBLOCK means alive but no data pending.
    matches!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

/// Stream authentication state events to an `Op::Watch` subscriber until
/// the connection closes. Events are filtered by caller (root sees all,
/// everyone else only their own user) and pushed through a bounded channel;
/// a subscriber that stops reading is dropped instead of accumulating
/// unbounded buffered events in the daemon.
fn handle_watch(daemon: &SharedDaemon, writer: &mut UnixStream, caller: Caller) {
    use std::io::Write;
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(crate::state::WATCH_BUFFER);
    {
        let mut watchers = match daemon.watchers.lock() {
            Ok(w) => w,
            Err(_) => return,
        };
        // Bound watch subscriptions: each occupies a connection slot for the
        // lifetime of the subscriber and receives every broadcast. Without
        // the caps a local account could open many watch streams to pin
        // server slots and/or grow the fan-out set.
        let per_uid = watchers
            .iter()
            .filter(|w| w.caller.uid == caller.uid)
            .count();
        if watchers.len() >= MAX_WATCHERS || per_uid >= MAX_WATCHERS_PER_UID {
            let _ = writer.write_all(
                serde_json::to_string(&Response::err(0, "too many watch subscribers"))
                    .map(|mut s| {
                        s.push('\n');
                        s
                    })
                    .unwrap_or_default()
                    .as_bytes(),
            );
            return;
        }
        watchers.push(crate::state::Watcher { caller, tx });
    }
    if let Ok(json) = serde_json::to_string(&hiro_core::proto::StateEvent::idle()) {
        let mut line = json;
        line.push('\n');
        let _ = writer.write_all(line.as_bytes());
    }
    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(line) => {
                if writer.write_all(line.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // No events for a while: verify the peer is still there so
                // a vanished client cannot pin this thread indefinitely.
                if !peer_alive(writer) {
                    break;
                }
            }
        }
    }
    // Sender is dropped here; broadcast_state prunes dead/full senders.
}

fn handle_conn(daemon: &SharedDaemon, stream: UnixStream) {
    let caller = match peer_credentials(&stream) {
        Some(c) => c,
        None => {
            log::warn!("connection without peer credentials; rejecting");
            return;
        }
    };
    let _ = set_read_timeout(&stream, CONN_IDLE_TIMEOUT_SECS);
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;

    loop {
        let line = match read_request_line(&mut reader, MAX_REQUEST_LINE) {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                log::warn!("dropping connection: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) if matches!(req.op, Op::Watch) => {
                handle_watch(daemon, &mut writer, caller);
                break;
            }
            Ok(req) if req.v == PROTOCOL_VERSION => dispatch(daemon, caller, req),
            Ok(_) => Response::err(0, "protocol version mismatch"),
            Err(e) => Response::err(0, format!("bad request: {e}")),
        };
        // Zeroize the serialized response: it may contain the plaintext
        // login password (keyring unlock), and must not linger in heap
        // memory after the connection write. Serialize directly into the
        // Zeroizing buffer so no intermediate un-wiped copy is produced.
        let mut out = zeroize::Zeroizing::new(Vec::<u8>::with_capacity(256));
        serde_json::to_writer(&mut *out, &response).expect("response serializes");
        out.push(b'\n');
        if writer.write_all(&out[..]).is_err() {
            break;
        }
    }
}

/// Maximum size of a single request line, matching the PAM client's cap.
/// `BufReader::lines()` has no length limit, so a local client streaming
/// data without a newline could grow daemon memory without bound.
const MAX_REQUEST_LINE: usize = 64 * 1024;

/// Read one newline-terminated request line with a hard length cap.
/// Returns `Ok(None)` on a clean EOF. The cap is enforced as bytes are
/// buffered, so a peer that never sends a newline cannot grow the buffer.
fn read_request_line(
    reader: &mut BufReader<UnixStream>,
    cap: usize,
) -> std::io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    loop {
        let (done, take) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                // EOF: emit a trailing partial line, or end cleanly.
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(finish_line(buf)))
                };
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(p) => (true, p + 1),
                None => (false, available.len()),
            }
        };
        if buf.len() + take > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request line too long",
            ));
        }
        {
            let available = reader.fill_buf()?;
            buf.extend_from_slice(&available[..take]);
        }
        reader.consume(take);
        if done {
            return Ok(Some(finish_line(buf)));
        }
    }
}

fn finish_line(mut buf: Vec<u8>) -> String {
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// PAM service names are config filenames. Anything outside a conservative
/// character set is replaced with "unknown" so a caller-supplied string can
/// never smuggle extra text into audit detail or approval events.
fn sanitize_service(service: &str) -> String {
    if !service.is_empty()
        && service.len() <= 64
        && service
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        service.to_string()
    } else {
        "unknown".into()
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
            want_keyring,
        } => {
            let service = sanitize_service(&service);
            match auth::verify(daemon, caller, &user, &service, timeout_ms, want_keyring) {
                Ok(result) => Response::ok(id, ResultValue::Verify(result)),
                Err(e) => Response::ok(id, ResultValue::Verify(verdict_from_error(&user, &e))),
            }
        }
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
        Op::KeyringSet { user, password } => match keyring_set(daemon, caller, &user, &password) {
            Ok(stored) => Response::ok(id, ResultValue::KeyringSet { stored }),
            Err(e) => Response::err(id, e),
        },
        Op::KeyringClear { user } => match keyring_clear(daemon, caller, &user) {
            Ok(removed) => Response::ok(id, ResultValue::KeyringCleared { removed }),
            Err(e) => Response::err(id, e),
        },
        Op::KeyringStatus { user } => match keyring_status(daemon, caller, &user) {
            Ok(s) => Response::ok(
                id,
                ResultValue::KeyringStatus {
                    enabled: s.0,
                    stored: s.1,
                },
            ),
            Err(e) => Response::err(id, e),
        },
        Op::Reload => {
            // Reloading re-reads configuration and can rebuild the
            // recognition pipeline: a root-only operation.
            if !caller.is_root() {
                return Response::err(
                    id,
                    format!("caller uid {} may not reload the daemon configuration", caller.uid),
                );
            }
            match reload(daemon) {
                Ok(()) => Response::ok(id, ResultValue::Reloaded),
                Err(e) => Response::err(id, e),
            }
        }
        Op::Prewarm => {
            // Acquiring the camera toggles the IR emitter and contends with
            // live requests: a root-only operation.
            if !caller.is_root() {
                return Response::err(
                    id,
                    format!("caller uid {} may not prewarm the camera", caller.uid),
                );
            }
            match prewarm(daemon) {
                Ok(()) => Response::ok(id, ResultValue::Prewarmed),
                Err(e) => Response::err(id, e),
            }
        }
        Op::Login { user, service } => {
            let service = sanitize_service(&service);
            match auth::record_login(daemon, caller, &user, &service) {
                Ok(()) => Response::ok(id, ResultValue::Login),
                Err(e) => Response::err(id, e.to_string()),
            }
        }
        Op::Approve {
            approval_id,
            user,
            allow,
            secret,
        } => match approve(daemon, caller, approval_id, &user, allow, secret) {
            Ok(()) => Response::ok(id, ResultValue::Approved),
            Err(e) => Response::err(id, e),
        },
        Op::Watch => Response::err(id, "watch is a streaming op"),
    }
}

fn verdict_from_error(user: &str, e: &AuthError) -> VerifyResult {
    let (reason, camera_ok) = match e {
        AuthError::RateLimited => ("rate_limited", true),
        AuthError::LockedOut => ("locked_out", true),
        AuthError::NoSuchUser(_) => ("no_such_user", true),
        AuthError::Denied(_) => ("denied", true),
        AuthError::Camera(_) => ("camera_unavailable", false),
        AuthError::Internal(_) => ("error", true),
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
        variance: None,
        motion: None,
        keyring_password: None,
        reason: reason.into(),
        threshold_used: 0.0,
    }
}

fn uid_of(user: &str) -> Result<u32, String> {
    crate::lookup::uid_of(user).ok_or_else(|| format!("no such user: {user}"))
}

/// Record an Allow/Disallow decision for a pending action approval.
///
/// Only the target user (or root) may decide. For approvals rendered on
/// the secure console (`approval.secure_desktop`), the caller must also be
/// root *and* present the per-approval secret that `hirod` gave to the
/// root-owned `hiro-approve` dialog it spawned — so a compromised user
/// session cannot silently approve. The id comes from the `approval_id`
/// field on the `approval_pending` StateEvent.
fn approve(
    daemon: &SharedDaemon,
    caller: Caller,
    approval_id: u64,
    user: &str,
    allow: bool,
    secret: Option<String>,
) -> Result<(), String> {
    let uid = uid_of(user)?;
    if !authorize(caller, Some(uid)) {
        return Err(format!(
            "caller uid {} may not decide approvals for {user}",
            caller.uid
        ));
    }
    let mut approvals = daemon
        .approvals
        .lock()
        .map_err(|_| "approvals lock poisoned".to_string())?;
    let pending = approvals
        .get_mut(&approval_id)
        .ok_or_else(|| format!("no pending approval {approval_id}"))?;
    if pending.user != user {
        return Err(format!(
            "approval {approval_id} is for {}, not {user}",
            pending.user
        ));
    }
    if pending.secret.is_some() {
        // Secure-console approval: the decision may only come from the
        // root-owned dialog process that holds this approval's secret.
        if !caller.is_root() || secret.as_deref() != pending.secret.as_deref() {
            return Err(
                "this approval is pinned to the secure console dialog; \
                 the caller must be root and present the dialog's secret"
                    .into(),
            );
        }
    }
    pending.decided = Some(allow);
    let service = pending.service.clone();
    drop(approvals);
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    audit(
        &store,
        Some(user),
        "approve",
        &format!("id={approval_id} service={service} allow={allow}"),
    );
    Ok(())
}

/// Check the caller may act for `user`, returning the user's uid.
fn require_authorized(caller: Caller, user: &str) -> Result<u32, String> {
    let uid = uid_of(user)?;
    if authorize(caller, Some(uid)) {
        Ok(uid)
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
    let cfg = daemon
        .cfg
        .read()
        .map_err(|_| "cfg lock poisoned".to_string())?;
    Ok(StatusResult {
        version: VERSION.into(),
        camera: camera.camera_path(),
        driver: camera.driver(),
        ir_detected: camera.is_ir_candidate(),
        emitter_active: Some(camera.emitter_active()),
        models_loaded: pipeline.loaded(),
        pipeline: pipeline.name().into(),
        templates: store.total_templates().map_err(|e| e.to_string())?,
        tpm_available: Some(daemon.km.tpm_available()),
        uptime_secs: daemon.started_at.elapsed().as_secs(),
        require_password_after_boot: cfg.security.require_password_after_boot,
        auto_threshold: cfg.recognition.auto_threshold,
        approval_enabled: cfg.approval.enabled,
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
    // Removing every template also drops the camera pinning record, so a
    // follow-up `hiro enroll` starts fresh (this is what the "run `hiro
    // clear` first" advice in the camera-changed error means).
    store.clear_camera_binding(user).map_err(|e| e.to_string())?;
    audit(
        &store,
        Some(user),
        "clear_templates",
        &format!("count={count}"),
    );
    Ok(count)
}

/// Seal and store the login password for keyring unlock.
///
/// The password is checked against the account before it is sealed, so a
/// typo at `hiro keyring set` time is caught immediately instead of at the
/// next login. Caller must be root or the target user.
fn keyring_set(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
    password: &str,
) -> Result<bool, String> {
    let uid = require_authorized(caller, user)?;
    if password.is_empty() {
        return Err("empty password".into());
    }
    if !daemon.password_checker.check(user, password) {
        return Err(format!(
            "password does not match the login password for {user}; \
             keyring unlock not stored"
        ));
    }
    // Bound the sealed password to its user so a ciphertext copied into
    // another account's row can never unseal.
    let ciphertext = daemon
        .km
        .seal(user.as_bytes(), password.as_bytes())
        .map_err(|e| format!("cannot seal keyring password: {e}"))?;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    store
        .upsert_user(user, Some(i64::from(uid)))
        .map_err(|e| e.to_string())?;
    store
        .set_login_secret(user, Some(&ciphertext))
        .map_err(|e| e.to_string())?;
    audit(&store, Some(user), "keyring_set", "login password sealed");
    Ok(true)
}

/// Drop the sealed login password.
fn keyring_clear(daemon: &SharedDaemon, caller: Caller, user: &str) -> Result<bool, String> {
    require_authorized(caller, user)?;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    let removed = store.clear_login_secret(user).map_err(|e| e.to_string())?;
    audit(
        &store,
        Some(user),
        "keyring_clear",
        "sealed password dropped",
    );
    Ok(removed)
}

/// Report whether keyring unlock is configured and a secret is stored.
fn keyring_status(
    daemon: &SharedDaemon,
    caller: Caller,
    user: &str,
) -> Result<(bool, bool), String> {
    require_authorized(caller, user)?;
    let enabled = daemon
        .cfg
        .read()
        .map_err(|_| "cfg lock poisoned".to_string())?
        .keyring
        .enabled;
    let store = daemon
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    let stored = store
        .login_secret(user)
        .map_err(|e| e.to_string())?
        .is_some();
    Ok((enabled, stored))
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
