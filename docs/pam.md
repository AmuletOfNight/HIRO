# PAM integration

`pam_hiro.so` is a `sufficient` auth module: a face match short-circuits
the password; anything else falls through to it.

## Debian / Ubuntu (pam-auth-update)

The package ships a `pam-auth-update` profile. Enable it:

```bash
sudo pam-auth-update      # tick "HIRO face authentication"
```

This adds `auth sufficient pam_hiro.so` to `common-auth`, covering `sudo`,
`su`, login, and the greeter in one shot.

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
| `sudo` hangs briefly | The module waits for the daemon (default 5 s). If the daemon is down, fix `hirod.service` — authentication still falls back to password |
| Nothing in the journal | Enable `debug` in the PAM line: `pam_hiro.so debug` |

## Removing

```bash
sudo pam-auth-update              # untick HIRO  (Debian/Ubuntu)
# or delete the sufficient line from /etc/pam.d/* (manual)
```
