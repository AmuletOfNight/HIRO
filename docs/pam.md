# PAM integration

`pam_hiro.so` is a `sufficient` auth module: a face match short-circuits
the password; anything else falls through to it.

## Debian / Ubuntu (pam-auth-update)

The package ships a `pam-auth-update` profile — **disabled by default**.
Installing the package must not silently change your authentication stack,
so face auth is opt-in:

```bash
sudo pam-auth-update      # tick "HIRO face authentication"
```

This adds `auth sufficient pam_hiro.so` to `common-auth`, covering
`sudo`, `su`, login, and the greeter in one shot. (The profile deliberately
does **not** carry the `keyring` argument — see the keyring section below.)

## Keyring unlock (GNOME Keyring / KWallet)

A face match normally short-circuits the auth stack, so the login keyring
never receives a password and GDM asks for it again after login ("the
keyring did not unlock"). HIRO can instead unlock it automatically:

```bash
# 1. Opt in (default is off) — /etc/hiro/config.toml:
#    [keyring]
#    enabled = true
#    services = ["gdm-password", "sddm", "lightdm", "lightdm-greeter", "login", "tty"]
sudo systemctl restart hirod

# 2. Store your login password once (re-run after changing it):
hiro keyring set

# 3. Make sure pam_hiro carries the `keyring` argument on the greeter
#    service. The packaged pam-auth-update profile intentionally omits it
#    (so enabling face auth never pulls in keyring unlock), and the
#    generated common-auth ordering puts pam_unix before pam_hiro, which
#    breaks the "inject authtok, fall through to pam_unix" flow. Add the
#    argument to the greeter service directly, BEFORE pam_unix, e.g.:
#      # /etc/pam.d/gdm-password
#      auth    sufficient    pam_hiro.so keyring
#      @include common-auth
#    (adapt for sddm / lightdm / login).
```

How it works: `pam_hiro.so` asks `hirod` for the sealed login password on a
face match. `hirod` unseals it (AES-256-GCM under the TPM-sealed data key)
and *re-verifies it against the account* before releasing it. The module
then injects it as `PAM_AUTHTK` and returns `PAM_AUTHINFO_UNAVAIL` instead
of short-circuiting, so `pam_unix ... try_first_pass` verifies it silently
and the keyring module (`auth optional pam_gnome_keyring.so`, already
present in gdm-password) unlocks it.

The password is released **only to root callers** (greeter and login stacks
run as root). A process running as the user never receives it — `hirod`
cannot distinguish a real greeter from same-uid malware, so the release is
root-gated to close that hole.

Safety: if you change your login password and forget to re-run
`hiro keyring set`, the stale secret is never released — face login keeps
working exactly as before, and the keyring simply stays locked until you
re-enroll. The stored value is ciphertext only; `hiro keyring clear` drops
it.

## Manual integration (any distro)

Add as the **first** `auth` line of the PAM service you want, plus the
session line (needed for the after-reboot password gate to arm — see
below):

```bash
# sudo /etc/pam.d/sudo
auth    sufficient    pam_hiro.so
auth    include       system-auth

# add to the session group of each login service (greeter, login, sshd, ...):
session optional    pam_hiro.so
```

Recommended services:

| File | Covers |
| --- | --- |
| `/etc/pam.d/sudo` | privilege escalation |
| `/etc/pam.d/su` | `su` |
| `/etc/pam.d/login` | TTY login |
| `/etc/pam.d/gdm` / `sddm` | greeter + lock screen |
| `/etc/pam.d/polkit-1` | graphical authorization prompts |

## Password required after reboot

Like Windows Hello and macOS Touch ID, face auth is disabled until the
account has been logged into since the last reboot
(`security.require_password_after_boot`, default on). After boot the first
login must use the password; that login arms face auth for the user for the
rest of the boot. The arming signal comes from `pam_hiro.so`'s session
hook (`session optional pam_hiro.so`), which reports the login to `hirod`.
The packaged pam-auth-update profile includes the hook; manual setups must
add the session line or face auth stays off after every reboot (set
`require_password_after_boot = false` to disable the gate entirely).

## Action approval for non-login services

By default (`[approval] enabled = true`), a face match alone is not enough
to authorize requests from *non-login* services: after a confident match,
`hirod` parks the request and asks for an explicit **Allow** / **Deny**
decision (shown by the status indicator, or on the secure console with
`approval.secure_desktop = true`). Login screens and `hiro test` bypass the
prompt because you trigger those yourself.

The PAM module simply waits for `hirod`'s final verdict, so nothing about
the PAM stack changes — `sudo`, `su`, and polkit keep the exact same
`auth sufficient pam_hiro.so` lines. The "sudo hangs briefly" behaviour is
now intentional: the extra delay is the decision window
(`approval.timeout_ms`, default 5 s). If you want instant matches
everywhere again, set `[approval] enabled = false` and restart `hirod`.

See `docs/security.md` ("Action approval gate") for the full behaviour and
the walk-away/timeout rules.

## polkit >= 127

polkit 127+ runs PAM inside a sandboxed helper. The package installs a
drop-in at
`/etc/systemd/system/polkit-agent-helper@.service.d/hiro.conf`.
`pam_hiro.so` is a thin client over the daemon's Unix socket and never
opens device nodes (hirod owns the camera), so **no sandbox relaxation is
installed** — the drop-in is a documentation stub. (Older builds set
`PrivateDevices=no` there, which exposed the host `/dev` to *every* polkit
authentication on the machine; that global weakening is gone.) If your
distro's helper ever needs camera nodes, add the narrow
`DeviceAllow=char-video4linux rw` entry instead of disabling
`PrivateDevices`.

## Testing without touching your live stack

`pamtester` exercises any service as your user:

```bash
sudo apt install pamtester
pamtester login "$USER" authenticate   # with HIRO enabled, it verifies your face
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Password prompt appears instantly | `journalctl -t hirod -g hiro_audit` — look for `reason=no_templates`, `camera_unavailable`, or `denied` |
| Face seen but verdict is `liveness_failed` | You were recognized but didn't move enough during the capture window. Keep gentle head movement through the whole scan (the gate needs both frame variance and landmark motion). The GNOME Shell extension — or `hiro-ui` on other desktops — shows live progress bars and a "move your head slightly" hint. |
| `sudo` hangs briefly | The module waits for the daemon (default 5 s). If the daemon is down, fix `hirod.service` — authentication still falls back to password |
| Nothing in the journal | Enable `debug` in the PAM line: `pam_hiro.so debug` |

## Removing

```bash
sudo pam-auth-update              # untick HIRO  (Debian/Ubuntu)
# or delete the sufficient line from /etc/pam.d/* (manual)
```
