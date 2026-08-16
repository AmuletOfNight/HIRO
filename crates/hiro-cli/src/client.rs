//! Thin IPC client for `hirod`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use hiro_core::proto::{Op, Outcome, Request, Response, ResultValue};
use hiro_core::PROTOCOL_VERSION;

pub const DEFAULT_SOCKET: &str = "/run/hirod/hirod.sock";

pub struct Client {
    socket: PathBuf,
    next_id: u64,
}

impl Client {
    pub fn new(socket: PathBuf) -> Self {
        Self { socket, next_id: 1 }
    }

    pub fn call(&mut self, op: Op) -> Result<ResultValue, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|e| format!("cannot connect to {}: {e}", self.socket.display()))?;
        let req = Request {
            v: PROTOCOL_VERSION,
            id,
            op,
        };
        let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader
            .read_line(&mut resp_line)
            .map_err(|e| e.to_string())?;
        let resp: Response =
            serde_json::from_str(&resp_line).map_err(|e| format!("bad response: {e}"))?;
        if resp.id != id {
            return Err(format!("response id mismatch ({} != {id})", resp.id));
        }
        match resp.outcome {
            Outcome::Ok { result } => Ok(result),
            Outcome::Err { error } => Err(error),
        }
    }
}

/// Default login name of the invoking user (from /etc/passwd).
pub fn current_user_name() -> Option<String> {
    let uid = nix::unistd::geteuid().as_raw();
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let mut parts = line.split(':');
        let name = parts.next()?.to_string();
        let _ = parts.next();
        if parts.next()?.parse::<u32>().ok() == Some(uid) {
            return Some(name);
        }
    }
    None
}
