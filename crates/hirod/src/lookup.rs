//! Local user database lookup (/etc/passwd) without NSS.

/// Resolve a login name to its uid via /etc/passwd.
/// Returns `None` for unknown users.
pub fn uid_of(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let mut parts = line.split(':');
        let n = parts.next()?;
        if n != name {
            continue;
        }
        let _ = parts.next();
        return parts.next()?.parse().ok();
    }
    None
}

/// Login name of the current euid, if known (test helper).
#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_resolves() {
        let name = current_user_name().expect("running user should exist in /etc/passwd");
        let uid = uid_of(&name).expect("lookup should succeed");
        assert_eq!(uid, nix::unistd::geteuid().as_raw());
    }

    #[test]
    fn unknown_user_is_none() {
        assert!(uid_of("definitely-not-a-user-xyz").is_none());
    }
}
