# PAM integration

`pam_hiro.so` is a `sufficient` auth module: a face match short-circuits
the password; anything else falls through to it.

## Debian / Ubuntu (pam-auth-update)

The package ships a `pam-auth-update` profile. Enable it:

```bash
sudo pam-auth-update      # tick "HIRO face authentication"
```

This adds `auth sufficient pam_hiro.so keyring` to `common-auth`, covering
`sudo`, `su`, login, and the greeter in one shot.

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

# 3. Make sure pam_hiro carries the `keyring` argument (the packaged
#    pam-auth-update profile already does):
sudo pam-auth-update
```

How it works: `pam_hiro.so` asks `hirod` for the sealed login password on a
face match. `hirod` unseals it (AES-256-GCM under the TPM-sealed data key)
and *re-verifies it against the account* before releasing it. The module
then injects it as `PAM_AUTHTK` and returns `PAM_AUTHINFO_UNAVAIL` instead
of short-circuiting, so `pam_unix ... try_first_pass` verifies it silently
and the keyring module (`auth optional pam_gnome_keyring.so`, already
present in gdm-password) unlocks it.

Safety: if you change your login password and forget to re-run
`hiro keyring set`, the stale secret is never released — face login keeps
working exactly as before, and the keyring simply stays locked until you
re-enroll. The stored value is ciphertext only; `hiro keyring clear` drops
it.

## Manual integration (any distro)

Add as the **first** `auth` line of the PAM service you want:

```bash
# sudo /etc/pam.d/sudo
auth    sufficient    pam_hiro.so
auth    include       system-auth
```

Recommended services:

| File | Covers |
| --- | --- |
| `/etc/pam.d/sudo` | privilege escalation |
| `/etc/pam.d/su` | `su` |
| `/etc/pam.d/login` | TTY login |
| `/etc/pam.d/gdm` / `sddm` | greeter + lock screen |
| `/etc/pam.d/polkit-1` | graphical authorization prompts |

## polkit >= 127

polkit 127+ runs PAM inside a sandboxed helper. The package installs a
drop-in at
`/etc/systemd/system/polkit-agent-helper@.service.d/hiro.conf`
(`PrivateDevices=no`) so the camera nodes and daemon socket stay visible.
Without it, face auth from graphical polkit prompts fails while sudo and
the lock screen keep working.

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
| Face seen but verdict is `liveness_failed` | You were recognized but didn't move enough during the capture window. Keep gentle head movement through the whole scan (the gate needs both frame variance and landmark motion). The GNOME Shell extension shows live progress bars and a "move your head slightly" hint. |
| `sudo` hangs briefly | The module waits for the daemon (default 5 s). If the daemon is down, fix `hirod.service` — authentication still falls back to password |
| Nothing in the journal | Enable `debug` in the PAM line: `pam_hiro.so debug` |

## Removing

```bash
sudo pam-auth-update              # untick HIRO  (Debian/Ubuntu)
# or delete the sufficient line from /etc/pam.d/* (manual)
```
