//! HIRO PAM module (`pam_hiro.so`).
//!
//! A thin client: reads the target user and service from PAM, asks the
//! `hirod` daemon for a face verdict over its Unix socket, and maps the
//! answer to a PAM status.
//!
//! Fail-closed semantics:
//!
//! * face match            -> PAM_SUCCESS (with `sufficient` this skips the
//!   password prompt)
//! * face match + keyring  -> PAM_AUTHINFO_UNAVAIL *after* the sealed login
//!   password has been injected as `PAM_AUTHTK`; the stack continues so
//!   `pam_unix` verifies it silently and the keyring module unlocks
//! * no match / no face    -> PAM_AUTH_ERR (password fallback proceeds)
//! * daemon unreachable or
//!   camera unavailable    -> PAM_AUTHINFO_UNAVAIL (password fallback)
//! * unexpected errors     -> PAM_SYSTEM_ERR
//!
//! Module arguments (in the PAM stack line):
//!   `socket=/path`   daemon socket (default /run/hirod/hirod.sock)
//!   `timeout_ms=N`   per-attempt cap in milliseconds (default 5000)
//!   `keyring`        on a face match, inject the daemon-verified login
//!                    password as `PAM_AUTHTK` and fall through to the rest
//!                    of the stack (unlock the login keyring). Only useful
//!                    on services that end with `pam_gnome_keyring` /
//!                    `pam_kwallet`, e.g. the greeter.
//!   `debug`          verbose logging via pam_syslog
//!
//! Typical stack line:
//!   `auth sufficient pam_hiro.so socket=/run/hirod/hirod.sock timeout_ms=5000 keyring`

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use hiro_core::proto::{Op, Outcome, Request, Response};
use hiro_core::PROTOCOL_VERSION;

const PAM_SUCCESS: c_int = 0;
const PAM_SYSTEM_ERR: c_int = 4;
const PAM_AUTH_ERR: c_int = 7;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_IGNORE: c_int = 25;
// Item types for pam_[gs]et_item (Linux-PAM _pam_types.h). These must
// match the values in the installed libpam exactly.
const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;
const PAM_AUTHTOK: c_int = 6;

const LOG_INFO: c_int = 6;
const LOG_DEBUG: c_int = 7;
const LOG_ERR: c_int = 3;

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_item(pamh: *const PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

#[derive(Default)]
struct ModuleOptions {
    socket: String,
    timeout_ms: u64,
    debug: bool,
    /// Ask `hirod` for the sealed login password on a face match and feed
    /// it to the rest of the stack as `PAM_AUTHTK` so `pam_gnome_keyring`
    /// / `pam_kwallet` can unlock the login keyring. Add this argument to
    /// the PAM line only on services whose stack ends with a keyring module
    /// (graphical greeters, session login).
    keyring: bool,
}

fn parse_options(argc: c_int, argv: *const *const c_char) -> ModuleOptions {
    let mut opts = ModuleOptions {
        socket: "/run/hirod/hirod.sock".into(),
        timeout_ms: 5_000,
        debug: false,
        keyring: false,
    };
    // SAFETY: argc/argv are supplied by libpam and valid for the duration
    // of the module call.
    unsafe {
        for i in 0..argc {
            let Some(arg) = argv.add(i as usize).as_ref() else {
                continue;
            };
            let Ok(arg) = CStr::from_ptr(*arg).to_str() else {
                continue;
            };
            if let Some(v) = arg.strip_prefix("socket=") {
                opts.socket = v.to_string();
            } else if let Some(v) = arg.strip_prefix("timeout_ms=") {
                if let Ok(ms) = v.parse() {
                    opts.timeout_ms = ms;
                }
            } else if arg == "debug" {
                opts.debug = true;
            } else if arg == "keyring" {
                opts.keyring = true;
            }
        }
    }
    opts
}

fn log(pamh: *const PamHandle, _opts: &ModuleOptions, priority: c_int, msg: &str) {
    // pam_syslog already carries the module/service context. The message is
    // passed as an argument to %s so embedded format specifiers are inert.
    let cmsg = CString::new(msg).unwrap_or_else(|_| CString::new("<unloggable>").unwrap());
    // SAFETY: cmsg is a valid NUL-terminated C string and matches the %s
    // format string, so no additional varargs are required.
    unsafe {
        let fmt = c"%s".as_ptr();
        pam_syslog(pamh, priority, fmt, cmsg.as_ptr());
    }
}

fn pam_item_string(pamh: *const PamHandle, item_type: c_int) -> Option<String> {
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: item buffer is writable storage; pam_get_item fills it.
    let rc = unsafe { pam_get_item(pamh, item_type, &mut item) };
    if rc != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: the returned pointer points to a NUL-terminated string owned
    // by libpam and valid for the duration of this call.
    unsafe {
        CStr::from_ptr(item.cast::<c_char>())
            .to_str()
            .ok()
            .map(str::to_owned)
    }
}

fn read_line(stream: &mut UnixStream, timeout_ms: u64) -> std::io::Result<String> {
    set_read_timeout(stream, timeout_ms)?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "daemon closed the connection",
                ));
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(String::from_utf8_lossy(&buf).into_owned());
                }
                if buf.len() > 64 * 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response too long",
                    ));
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(e),
        }
    }
}

fn set_read_timeout(stream: &UnixStream, timeout_ms: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Timeval {
        tv_sec: libc::time_t,
        tv_usec: libc::suseconds_t,
    }
    let tv = Timeval {
        tv_sec: (timeout_ms / 1000) as libc::time_t,
        tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
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

fn ask_daemon(
    opts: &ModuleOptions,
    user: &str,
    service: &str,
) -> Option<hiro_core::proto::VerifyResult> {
    let mut stream = UnixStream::connect(&opts.socket).ok()?;
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 0,
        op: Op::Verify {
            user: user.into(),
            service: service.into(),
            timeout_ms: opts.timeout_ms,
            want_keyring: opts.keyring,
        },
    };
    let mut line = serde_json::to_string(&req).ok()?;
    line.push('\n');
    stream.write_all(line.as_bytes()).ok()?;
    let resp_line = read_line(&mut stream, opts.timeout_ms + 2_000).ok()?;
    let resp: Response = serde_json::from_str(&resp_line).ok()?;
    match resp.outcome {
        Outcome::Ok { result } => match result {
            hiro_core::proto::ResultValue::Verify(v) => Some(v),
            _ => None,
        },
        Outcome::Err { .. } => None,
    }
}

/// Inject `password` as `PAM_AUTHTK` so the remainder of the stack
/// (`pam_unix ... try_first_pass`, `pam_gnome_keyring`) can use it without
/// prompting. libpam copies the string, so the caller may drop it after.
fn set_authtok(pamh: *const PamHandle, password: &str) -> c_int {
    let Ok(cpassword) = CString::new(password) else {
        return PAM_SYSTEM_ERR;
    };
    // SAFETY: cpassword is a valid NUL-terminated string; libpam strdups
    // it into the handle before returning.
    unsafe { pam_set_item(pamh, PAM_AUTHTOK, cpassword.as_ptr().cast()) }
}

/// The core authenticate implementation, panic-free across the FFI edge.
fn authenticate_impl(pamh: *const PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    let opts = parse_options(argc, argv);

    let Some(user) = pam_item_string(pamh, PAM_USER) else {
        return PAM_AUTH_ERR;
    };
    let service = pam_item_string(pamh, PAM_SERVICE).unwrap_or_else(|| "unknown".into());

    if opts.debug {
        log(
            pamh,
            &opts,
            LOG_DEBUG,
            &format!("hiro: verifying {user} via {}", opts.socket),
        );
    }

    match ask_daemon(&opts, &user, &service) {
        Some(verdict) if verdict.matched => {
            if let Some(password) = verdict.keyring_password.as_deref() {
                if set_authtok(pamh, password) == PAM_SUCCESS {
                    log(
                        pamh,
                        &opts,
                        LOG_INFO,
                        &format!(
                            "hiro: face match for {user} (score={:?}); keyring authtok injected",
                            verdict.score
                        ),
                    );
                    // Fall through to `pam_unix ... try_first_pass` (which
                    // verifies the password without prompting) and then to
                    // the keyring module, instead of short-circuiting.
                    return PAM_AUTHINFO_UNAVAIL;
                }
                log(
                    pamh,
                    &opts,
                    LOG_ERR,
                    "hiro: failed to set PAM_AUTHTK; skipping keyring unlock",
                );
            }
            log(
                pamh,
                &opts,
                LOG_INFO,
                &format!("hiro: face match for {user} (score={:?})", verdict.score),
            );
            PAM_SUCCESS
        }
        Some(verdict) if !verdict.camera_ok => {
            log(
                pamh,
                &opts,
                LOG_INFO,
                "hiro: camera unavailable; falling back to password",
            );
            PAM_AUTHINFO_UNAVAIL
        }
        Some(_) => PAM_AUTH_ERR,
        None => {
            log(
                pamh,
                &opts,
                LOG_ERR,
                "hiro: daemon unreachable; falling back to password",
            );
            PAM_AUTHINFO_UNAVAIL
        }
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *const PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let _ = flags;
    std::panic::catch_unwind(|| authenticate_impl(pamh, argc, argv)).unwrap_or(PAM_SYSTEM_ERR)
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// Tell `hirod` that `user` just logged in, so face auth arms for them
/// until the next reboot. Best-effort and intentionally side-effect free:
/// any failure is swallowed, and the session always opens.
fn notify_login(opts: &ModuleOptions, user: &str, service: &str) {
    let mut stream = match UnixStream::connect(&opts.socket) {
        Ok(s) => s,
        Err(_) => return,
    };
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 0,
        op: Op::Login {
            user: user.into(),
            service: service.into(),
        },
    };
    let mut line = match serde_json::to_string(&req) {
        Ok(l) => l,
        Err(_) => return,
    };
    line.push('\n');
    if stream.write_all(line.as_bytes()).is_err() {
        return;
    }
    // Consume the daemon's reply so the connection completes cleanly; the
    // outcome is intentionally ignored (fail-open).
    let _ = read_line(&mut stream, 2_000);
}

fn open_session_impl(pamh: *const PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    let opts = parse_options(argc, argv);
    let Some(user) = pam_item_string(pamh, PAM_USER) else {
        return PAM_SUCCESS;
    };
    let service = pam_item_string(pamh, PAM_SERVICE).unwrap_or_else(|| "unknown".into());
    if opts.debug {
        log(
            pamh,
            &opts,
            LOG_DEBUG,
            &format!("hiro: recording login for {user} via {}", opts.socket),
        );
    }
    notify_login(&opts, &user, &service);
    PAM_SUCCESS
}

/// Session open: a login completed successfully (after this, the PAM auth
/// stack has accepted the user's credentials). Report it to `hirod` so the
/// after-reboot gate arms face auth for this user until the next boot.
#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *const PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let _ = flags;
    std::panic::catch_unwind(|| open_session_impl(pamh, argc, argv)).unwrap_or(PAM_SUCCESS)
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}
