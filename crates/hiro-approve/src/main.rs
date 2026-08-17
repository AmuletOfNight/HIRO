//! `hiro-approve`: secure-desktop approval dialog for the HIRO action gate.
//!
//! `hirod` launches this on a dedicated VT when `approval.secure_desktop`
//! is enabled and a non-login request (sudo, lock screen, polkit, ...)
//! passes the face scan. The dialog switches to that VT — a secure console
//! the user's (potentially compromised) session cannot draw on — renders an
//! Allow/Deny prompt full-screen, sends the decision back to the daemon
//! over its Unix socket, and restores the previous VT.
//!
//! Usage (spawned by `hirod`, root):
//!
//! ```text
//! hiro-approve --vt=8 --socket=/run/hirod/hirod.sock --user=alice \
//!              --approval-id=1 --service=sudo --timeout-ms=5000
//! ```
//!
//! Keys: `Enter`/`Y` = allow, `Esc`/`N`/`Q` = deny. The dialog closes early
//! if the daemon resolves the window itself (timeout) — it watches the
//! daemon's state stream for the terminal event. It also closes when the
//! daemon reports the user stepped away (`user_present: false`); `hirod`
//! re-opens the dialog when the user steps back into the frame.
//!
//! The prompt is drawn as a centered, full-screen layout using the VT's
//! reported size (`TIOCGWINSZ`), with large block-letter ALLOW/DENY keys and
//! countdown so it is readable from a distance on the secure console.

use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hiro_core::proto::{Op, Outcome, Request, Response, StateEvent};
use hiro_core::PROTOCOL_VERSION;

// ioctl request codes from <linux/vt.h>.
const VT_ACTIVATE: libc::c_ulong = 0x5606;
const VT_WAITACTIVE: libc::c_ulong = 0x5607;

const DEFAULT_SOCKET: &str = "/run/hirod/hirod.sock";
/// How long the final status line stays on screen before the VT is
/// restored, so the user sees whether the decision went through.
const RESULT_PAUSE_MS: u64 = 600;

struct Args {
    vt: u32,
    socket: String,
    user: String,
    approval_id: u64,
    service: String,
    timeout_ms: u64,
}

fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut out = Args {
        vt: 8,
        socket: DEFAULT_SOCKET.into(),
        user: String::new(),
        approval_id: 0,
        service: "unknown".into(),
        timeout_ms: 5_000,
    };
    for arg in args {
        let Some((key, value)) = arg.split_once('=') else {
            return Err(format!("unexpected argument: {arg}"));
        };
        match key {
            "--vt" => {
                out.vt = value
                    .parse()
                    .map_err(|_| format!("bad --vt value: {value}"))?
            }
            "--socket" => out.socket = value.into(),
            "--user" => out.user = value.into(),
            "--approval-id" => {
                out.approval_id = value
                    .parse()
                    .map_err(|_| format!("bad --approval-id value: {value}"))?
            }
            "--service" => out.service = value.into(),
            "--timeout-ms" => {
                out.timeout_ms = value
                    .parse()
                    .map_err(|_| format!("bad --timeout-ms value: {value}"))?
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if out.user.is_empty() || out.approval_id == 0 {
        return Err("--user and --approval-id are required".into());
    }
    if out.vt == 0 {
        return Err("--vt must be at least 1".into());
    }
    Ok(out)
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hiro-approve: {e}");
            eprintln!("usage: hiro-approve --vt=N --user=U --approval-id=N [--socket=PATH] [--service=S] [--timeout-ms=N]");
            std::process::exit(2);
        }
    };
    std::process::exit(run(&args));
}

fn run(args: &Args) -> i32 {
    let return_vt = active_vt().unwrap_or(7);
    let switched = return_vt != args.vt;

    // Switch to the secure console first, so the prompt can never render
    // inside the user's session.
    if let Err(e) = switch_vt(args.vt) {
        eprintln!("hiro-approve: cannot switch to VT {}: {e}", args.vt);
        return 1;
    }

    let tty_path = format!("/dev/tty{}", args.vt);
    let mut tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tty_path)
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hiro-approve: cannot open {tty_path}: {e}");
            if switched {
                let _ = switch_vt(return_vt);
            }
            return 1;
        }
    };
    let fd = tty.as_raw_fd();
    let Some(_raw) = RawMode::enter(fd) else {
        eprintln!("hiro-approve: cannot set raw mode on {tty_path}");
        if switched {
            let _ = switch_vt(return_vt);
        }
        return 1;
    };

    // Watch the daemon's state stream so a daemon-side resolution (timeout
    // or the user leaving the frame) closes the dialog promptly.
    let (tx, rx) = mpsc::channel::<WatchMsg>();
    let watcher = spawn_watcher(&args.socket, tx);

    let start = Instant::now();
    let mut exit_code: Option<i32> = None;
    let mut stepped_away = false;

    draw(&mut tty, fd, args, 0, Status::Prompt);
    while exit_code.is_none() {
        // Daemon resolved the window on its own, or the user stepped away?
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WatchMsg::Closed => {
                    draw(&mut tty, fd, args, elapsed_ms(&start), Status::Closed);
                    exit_code = Some(1);
                }
                WatchMsg::Away => {
                    draw(&mut tty, fd, args, elapsed_ms(&start), Status::Away);
                    stepped_away = true;
                    exit_code = Some(0);
                }
                WatchMsg::Unreachable => {
                    draw(&mut tty, fd, args, elapsed_ms(&start), Status::Unreachable);
                    exit_code = Some(1);
                }
            }
        }
        if exit_code.is_some() {
            break;
        }

        let elapsed = elapsed_ms(&start);
        if elapsed >= args.timeout_ms {
            draw(&mut tty, fd, args, elapsed, Status::TimedOut);
            exit_code = Some(1);
            break;
        }

        // Key input: raw mode sets VMIN=0/VTIME=1, so read returns after at
        // most ~100ms with zero or one byte.
        let mut key = [0u8; 1];
        let n = read_key(fd, &mut key);
        if n == 1 {
            match classify_key(key[0]) {
                Key::Allow => {
                    draw(&mut tty, fd, args, elapsed, Status::Sending(true));
                    let ok = send_approve(args, true);
                    draw(&mut tty, fd, args, elapsed, Status::Result { ok, allow: true });
                    exit_code = Some(if ok { 0 } else { 1 });
                }
                Key::Deny => {
                    draw(&mut tty, fd, args, elapsed, Status::Sending(false));
                    let ok = send_approve(args, false);
                    draw(&mut tty, fd, args, elapsed, Status::Result { ok, allow: false });
                    exit_code = Some(if ok { 0 } else { 1 });
                }
                Key::Ignore => {}
            }
        } else if n < 0 {
            exit_code = Some(1);
            break;
        }

        if exit_code.is_none() {
            draw(&mut tty, fd, args, elapsed_ms(&start), Status::Prompt);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    // Let the user read the final status before returning to their desktop.
    // Skip the pause when the user stepped away: nobody is there to read it,
    // and returning to the desktop VT promptly avoids racing a dialog that
    // `hirod` re-spawns when the user steps back into the frame.
    if matches!(exit_code, Some(0 | 1)) && !stepped_away {
        std::thread::sleep(Duration::from_millis(RESULT_PAUSE_MS));
    }
    drop(_raw);
    if switched {
        let _ = switch_vt(return_vt);
    }
    let _ = watcher.join();
    exit_code.unwrap_or(1)
}

fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

enum Key {
    Allow,
    Deny,
    Ignore,
}

fn classify_key(b: u8) -> Key {
    match b {
        b'\r' | b'\n' | b'y' | b'Y' => Key::Allow,
        b'\x1b' | b'n' | b'N' | b'q' | b'Q' => Key::Deny,
        _ => Key::Ignore,
    }
}

enum Status {
    Prompt,
    Sending(bool),
    Result { ok: bool, allow: bool },
    TimedOut,
    Closed,
    /// The user stepped away from the camera; the dialog dismisses and
    /// `hirod` re-opens it if they come back.
    Away,
    Unreachable,
}

/// One on-screen text row: the display text (may contain ANSI SGR codes) plus
/// its plain-text display width, used for horizontal centering.
struct Row {
    text: String,
    width: usize,
}

impl Row {
    /// Build a row from plain text and an optional SGR parameter string
    /// (e.g. "1;32" for bold green). Empty style means no colour.
    fn new(plain: &str, style: &str) -> Self {
        let width = plain.chars().count();
        let text = if style.is_empty() {
            plain.to_string()
        } else {
            format!("\x1b[{style}m{plain}\x1b[0m")
        };
        Self { text, width }
    }

    fn blank() -> Self {
        Self {
            text: String::new(),
            width: 0,
        }
    }
}

/// 5x5 block-letter glyph used for the big ALLOW / DENY keys and the
/// countdown. Unsupported characters render as spaces so a stray service
/// name can never break the layout.
fn glyph(c: char) -> [&'static str; 5] {
    match c {
        'A' => [" ### ", "#   #", "#   #", "#####", "#   #"],
        'B' => ["#### ", "#   #", "#### ", "#   #", "#### "],
        'C' => [" ### ", "#    ", "#    ", "#    ", " ### "],
        'D' => ["#### ", "#   #", "#   #", "#   #", "#### "],
        'E' => ["#####", "#    ", "#### ", "#    ", "#####"],
        'F' => ["#####", "#    ", "#### ", "#    ", "#    "],
        'G' => [" ### ", "#    ", "#  ##", "#   #", " ### "],
        'H' => ["#   #", "#   #", "#####", "#   #", "#   #"],
        'I' => ["#####", "  #  ", "  #  ", "  #  ", "#####"],
        'J' => ["  ###", "   # ", "   # ", "   # ", " ### "],
        'K' => ["#   #", "#  # ", "###  ", "#  # ", "#   #"],
        'L' => ["#    ", "#    ", "#    ", "#    ", "#####"],
        'M' => ["#   #", "## ##", "# # #", "#   #", "#   #"],
        'N' => ["#   #", "##  #", "# # #", "#  ##", "#   #"],
        'O' => [" ### ", "#   #", "#   #", "#   #", " ### "],
        'P' => ["#### ", "#   #", "#### ", "#    ", "#    "],
        'Q' => [" ### ", "#   #", "#   #", "#  # ", " ## #"],
        'R' => ["#### ", "#   #", "#### ", "#  # ", "#   #"],
        'S' => [" ####", "#    ", " ### ", "    #", "#### "],
        'T' => ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
        'U' => ["#   #", "#   #", "#   #", "#   #", " ### "],
        'V' => ["#   #", "#   #", "#   #", " # # ", "  #  "],
        'W' => ["#   #", "#   #", "# # #", "# # #", "#   #"],
        'X' => ["#   #", " # # ", "  #  ", " # # ", "#   #"],
        'Y' => ["#   #", "#   #", " ### ", "  #  ", "  #  "],
        'Z' => ["#####", "   # ", "  #  ", " #   ", "#####"],
        '0' => [" ### ", "#   #", "#   #", "#   #", " ### "],
        '1' => ["  #  ", " ##  ", "  #  ", "  #  ", "#####"],
        '2' => [" ### ", "#   #", "  ## ", " #   ", "#####"],
        '3' => ["#####", "    #", " ####", "    #", "#####"],
        '4' => ["   # ", "  ## ", " # # ", "#####", "   # "],
        '5' => ["#####", "#    ", "#### ", "    #", "#### "],
        '6' => [" ### ", "#    ", "#### ", "#   #", " ### "],
        '7' => ["#####", "    #", "   # ", "  #  ", "  #  "],
        '8' => [" ### ", "#   #", " ### ", "#   #", " ### "],
        '9' => [" ### ", "#   #", " ####", "    #", " ### "],
        '.' => ["     ", "     ", "     ", "     ", " ### "],
        '-' => ["     ", "     ", "#####", "     ", "     "],
        _ => ["     ", "     ", "     ", "     ", "     "],
    }
}

/// Render `word` as 5x5 block letters, one string per row, with a single
/// space column between letters.
fn render_big(word: &str) -> Vec<String> {
    let mut rows = vec![String::new(); 5];
    for (i, c) in word.chars().enumerate() {
        let g = glyph(c);
        for (r, row) in rows.iter_mut().enumerate() {
            if i > 0 {
                row.push(' ');
            }
            row.push_str(g[r]);
        }
    }
    rows
}

/// The tty's size in (rows, cols); falls back to 24x80 when it cannot be
/// read (e.g. a freshly opened VT).
fn terminal_size(fd: i32) -> (usize, usize) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a valid tty descriptor and `ws` is writable storage.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0
        && ws.ws_col > 0
        && ws.ws_row > 0
    {
        (ws.ws_row as usize, ws.ws_col as usize)
    } else {
        (24, 80)
    }
}

fn draw(tty: &mut dyn Write, fd: i32, args: &Args, elapsed_ms: u64, status: Status) {
    let (rows, cols) = terminal_size(fd);
    draw_at(tty, rows, cols, args, elapsed_ms, status);
}

/// Render the prompt for a terminal of the given `(rows, cols)`; split from
/// `draw` so the layout is testable without a real tty.
fn draw_at(
    tty: &mut dyn Write,
    rows: usize,
    cols: usize,
    args: &Args,
    elapsed_ms: u64,
    status: Status,
) {
    let cols = cols.max(40);
    let rows = rows.max(10);

    let remaining = args.timeout_ms.saturating_sub(elapsed_ms);
    let secs = remaining as f32 / 1000.0;

    // Build the full-screen layout, top to bottom.
    let mut lines: Vec<Row> = Vec::new();

    lines.push(Row::new("HIRO — authentication approval", "1;44"));
    lines.push(Row::new(
        &format!("Service: {}    User: {}", args.service, args.user),
        "2",
    ));
    lines.push(Row::blank());

    // Big countdown.
    for l in render_big(&format!("{secs:.1}")) {
        lines.push(Row::new(&l, "1;33"));
    }
    lines.push(Row::blank());

    // Big Allow / Deny keys.
    for l in render_big("ALLOW") {
        lines.push(Row::new(&l, "1;32"));
    }
    for l in render_big("DENY") {
        lines.push(Row::new(&l, "1;31"));
    }
    lines.push(Row::blank());

    lines.push(Row::new("ENTER or Y = allow      ESC, N or Q = deny", "1"));
    lines.push(Row::blank());

    match status {
        Status::Prompt => {}
        Status::Sending(allow) => {
            lines.push(Row::new(
                &format!(
                    "Sending your decision ({}…)",
                    if allow { "allow" } else { "deny" }
                ),
                "1;36",
            ));
        }
        Status::Result { ok, allow } => {
            lines.push(Row::new(
                &format!(
                    "{} — {}.",
                    if ok {
                        "Decision sent"
                    } else {
                        "Decision not recorded"
                    },
                    if allow { "allowing" } else { "denying" }
                ),
                if ok { "1;32" } else { "1;31" },
            ));
            if !ok {
                lines.push(Row::new(
                    "The request may already have been resolved.",
                    "31",
                ));
            }
        }
        Status::TimedOut => {
            lines.push(Row::new(
                "Time limit reached — the request was not approved.",
                "1;31",
            ));
        }
        Status::Closed => {
            lines.push(Row::new(
                "The request was resolved (timed out or you stepped away).",
                "1;31",
            ));
        }
        Status::Away => {
            lines.push(Row::new(
                "You stepped away — prompt dismissed. Face the camera again to decide.",
                "1;33",
            ));
        }
        Status::Unreachable => {
            lines.push(Row::new("Cannot reach the HIRO daemon.", "1;31"));
        }
    }

    // Clear, then paint the block vertically and horizontally centred.
    let mut out = String::new();
    out.push_str("\x1b[2J\x1b[H"); // clear screen, home cursor
    for _ in 0..(rows.saturating_sub(lines.len()) / 2) {
        out.push_str("\r\n");
    }
    for line in &lines {
        let pad = cols.saturating_sub(line.width) / 2;
        for _ in 0..pad {
            out.push(' ');
        }
        out.push_str(&line.text);
        out.push_str("\r\n");
    }
    let _ = tty.write_all(out.as_bytes());
    let _ = tty.flush();
}

fn read_key(fd: i32, key: &mut [u8; 1]) -> isize {
    // SAFETY: fd is a valid tty descriptor and `key` is one writable byte.
    unsafe { libc::read(fd, key.as_mut_ptr().cast(), 1) }
}

enum WatchMsg {
    /// The daemon broadcast a terminal success/failure event: the window
    /// closed without (or in addition to) our decision.
    Closed,
    /// The daemon reported the user stepped away from the camera
    /// (`user_present: false`): dismiss the dialog; `hirod` re-opens it if
    /// the user steps back into the frame.
    Away,
    /// The daemon socket could not be reached.
    Unreachable,
}

/// Follow the daemon's state stream and report when the approval window
/// closes so the dialog can exit instead of counting down on a resolved
/// request. Also reports when the user steps away so the prompt does not
/// sit on a deserted secure console.
fn spawn_watcher(socket: &str, tx: mpsc::Sender<WatchMsg>) -> std::thread::JoinHandle<()> {
    let socket = socket.to_string();
    std::thread::spawn(move || {
        let mut stream = match UnixStream::connect(&socket) {
            Ok(s) => s,
            Err(_) => {
                let _ = tx.send(WatchMsg::Unreachable);
                return;
            }
        };
        let req = Request {
            v: PROTOCOL_VERSION,
            id: 0,
            op: Op::Watch,
        };
        let mut line = match serde_json::to_string(&req) {
            Ok(l) => l,
            Err(_) => return,
        };
        line.push('\n');
        if stream.write_all(line.as_bytes()).is_err() {
            let _ = tx.send(WatchMsg::Unreachable);
            return;
        }
        let reader = match stream.try_clone() {
            Ok(c) => std::io::BufReader::new(c),
            Err(_) => {
                let _ = tx.send(WatchMsg::Unreachable);
                return;
            }
        };
        let mut reader = reader;
        let mut buf = String::new();
        loop {
            buf.clear();
            match reader.read_line(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(WatchMsg::Unreachable);
                    return;
                }
                Ok(_) => {}
            }
            let ev: StateEvent = match serde_json::from_str(buf.trim_end()) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if ev.user_present == Some(false) {
                // The user stepped away; dismiss the dialog (hirod re-opens
                // it if they come back).
                let _ = tx.send(WatchMsg::Away);
                return;
            }
            if matches!(ev.state.as_str(), "success" | "failure") {
                let _ = tx.send(WatchMsg::Closed);
                return;
            }
        }
    })
}

/// Send the Allow/Disallow decision to the daemon and report whether it
/// accepted the request (an already-resolved approval returns an error).
fn send_approve(args: &Args, allow: bool) -> bool {
    let mut stream = match UnixStream::connect(&args.socket) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let req = Request {
        v: PROTOCOL_VERSION,
        id: 0,
        op: Op::Approve {
            approval_id: args.approval_id,
            user: args.user.clone(),
            allow,
        },
    };
    let mut line = match serde_json::to_string(&req) {
        Ok(l) => l,
        Err(_) => return false,
    };
    line.push('\n');
    if stream.write_all(line.as_bytes()).is_err() {
        return false;
    }
    let mut reader = std::io::BufReader::new(stream);
    let mut resp_line = String::new();
    if reader.read_line(&mut resp_line).is_err() {
        return false;
    }
    let resp: Response = match serde_json::from_str(resp_line.trim_end()) {
        Ok(r) => r,
        Err(_) => return false,
    };
    matches!(resp.outcome, Outcome::Ok { .. })
}

/// Switch the foreground console to `vt` (root required).
fn switch_vt(vt: u32) -> std::io::Result<()> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/console")?;
    let fd = f.as_raw_fd();
    // SAFETY: fd is a valid console descriptor; both ioctls take the VT
    // number as an integer argument.
    let rc = unsafe { libc::ioctl(fd, VT_ACTIVATE, vt as libc::c_int) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::ioctl(fd, VT_WAITACTIVE, vt as libc::c_int) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The currently active VT number (e.g. "tty7" -> 7), if readable.
fn active_vt() -> Option<u32> {
    let s = std::fs::read_to_string("/sys/class/tty/tty0/active").ok()?;
    s.trim().strip_prefix("tty")?.parse().ok()
}

/// termios raw mode with a ~100ms read timeout (VMIN=0, VTIME=1) so the
/// main loop can poll keys while still redrawing the countdown. Restored on
/// drop.
struct RawMode {
    fd: i32,
    orig: libc::termios,
}

impl RawMode {
    fn enter(fd: i32) -> Option<Self> {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is a valid tty descriptor and `t` is writable storage.
        if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
            return None;
        }
        let orig = t;
        t.c_lflag &= !(libc::ICANON | libc::ECHO);
        t.c_cc[libc::VMIN] = 0;
        t.c_cc[libc::VTIME] = 1;
        // SAFETY: fd is a valid tty descriptor and `t` is a valid termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) } != 0 {
            return None;
        }
        Some(Self { fd, orig })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: fd is still valid and `orig` was captured by tcgetattr.
        unsafe {
            let _ = libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spawn_args() {
        let args = parse_args(
            vec![
                "--vt=9".to_string(),
                "--socket=/tmp/h.sock".to_string(),
                "--user=alice".to_string(),
                "--approval-id=42".to_string(),
                "--service=sudo".to_string(),
                "--timeout-ms=3000".to_string(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(args.vt, 9);
        assert_eq!(args.socket, "/tmp/h.sock");
        assert_eq!(args.user, "alice");
        assert_eq!(args.approval_id, 42);
        assert_eq!(args.service, "sudo");
        assert_eq!(args.timeout_ms, 3000);
    }

    #[test]
    fn defaults_apply() {
        let args =
            parse_args(vec!["--user=bob".to_string(), "--approval-id=1".to_string()].into_iter())
                .unwrap();
        assert_eq!(args.vt, 8);
        assert_eq!(args.socket, DEFAULT_SOCKET);
        assert_eq!(args.timeout_ms, 5000);
    }

    #[test]
    fn rejects_missing_identity() {
        assert!(parse_args(vec!["--user=bob".to_string()].into_iter()).is_err());
        assert!(parse_args(vec!["--approval-id=1".to_string()].into_iter()).is_err());
    }

    #[test]
    fn key_mapping() {
        assert!(matches!(classify_key(b'\r'), Key::Allow));
        assert!(matches!(classify_key(b'\n'), Key::Allow));
        assert!(matches!(classify_key(b'y'), Key::Allow));
        assert!(matches!(classify_key(b'Y'), Key::Allow));
        assert!(matches!(classify_key(b'\x1b'), Key::Deny));
        assert!(matches!(classify_key(b'n'), Key::Deny));
        assert!(matches!(classify_key(b'q'), Key::Deny));
        assert!(matches!(classify_key(b'x'), Key::Ignore));
    }

    fn test_args() -> Args {
        Args {
            vt: 8,
            socket: "/tmp/h.sock".into(),
            user: "alice".into(),
            approval_id: 42,
            service: "sudo".into(),
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn render_big_produces_uniform_block_rows() {
        for word in ["ALLOW", "DENY"] {
            let rows = render_big(word);
            assert_eq!(rows.len(), 5, "{word}");
            let widths: std::collections::HashSet<usize> =
                rows.iter().map(|r| r.chars().count()).collect();
            assert_eq!(widths.len(), 1, "{word} rows must all be equal width");
            assert!(widths.iter().all(|w| *w >= 20), "{word} should be big");
        }
    }

    #[test]
    fn render_big_renders_countdown_digits_and_dot() {
        let rows = render_big("29.5");
        assert_eq!(rows.len(), 5);
        // The digit glyphs include a solid bottom row ("#####") for the '2'.
        assert!(rows[4].contains("#####"));
        // The period glyph only draws on the bottom row.
        assert!(rows[4].contains(" ### "));
    }

    #[test]
    fn draw_centers_layout_and_includes_keys() {
        let mut out = Vec::new();
        draw_at(&mut out, 40, 100, &test_args(), 0, Status::Prompt);
        let text = String::from_utf8(out).unwrap();

        // Title and hints present.
        assert!(text.contains("HIRO — authentication approval"));
        assert!(text.contains("ENTER or Y = allow"));

        // Big ALLOW / DENY blocks present.
        assert!(text.contains("#####"));
        assert!(text.contains("#   #"));

        // Countdown shows the full remaining window, rendered big.
        let countdown_row = render_big("5.0")[0].clone();
        assert!(text.contains(&countdown_row));

        // Every painted line fits and is horizontally centred: leading pad
        // spaces = (cols - content width) / 2. Content width is the full
        // stripped line minus the pad itself (block letters legitimately
        // begin with spaces, e.g. the "5" glyph's "    #" row). ANSI
        // sequences are ignored for width.
        for line in text.lines().skip(1) {
            let line = line.trim_end_matches('\r');
            let stripped = strip_ansi(line);
            if stripped.trim().is_empty() {
                continue;
            }
            let leading = line.chars().take_while(|c| *c == ' ').count();
            let content_width = stripped.chars().count().saturating_sub(leading);
            assert_eq!(
                leading,
                (100 - content_width) / 2,
                "uncentered line: {stripped:?}"
            );
        }

        // Vertically centred: the block starts partway down a 40-row screen.
        let first_content = text
            .lines()
            .position(|l| {
                let l = l.trim_end_matches('\r');
                !strip_ansi(l).trim().is_empty()
            })
            .unwrap();
        assert!(first_content > 0, "layout should start below the top edge");
    }

    #[test]
    fn draw_shows_step_away_status() {
        let mut out = Vec::new();
        draw_at(&mut out, 24, 80, &test_args(), 0, Status::Away);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("stepped away"));
    }

    /// Strip ANSI escape sequences (used by `draw`) so width checks see
    /// only the visible text.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                while let Some(n) = chars.next() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }
}
