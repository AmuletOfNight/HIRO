# HIRO — Windows Hello-style face authentication for Linux

HIRO uses your laptop's built-in **Windows Hello IR camera** to authenticate
through PAM: login, lock screen, `sudo`, `su`, and polkit prompts. It aims
for the Windows Hello security bar: IR-only enforcement, anti-spoof
liveness, encrypted templates, camera pinning, rate limiting, and a full
audit trail.

- **Offline** — all inference runs locally via ONNX Runtime; no network, no
  telemetry, ever.
- **No images stored** — only encrypted 512-D face embeddings.
- **Fail closed** — if the daemon or camera misbehaves, you always fall
  back to your password; authentication never blocks.
- **Auto-calibrated thresholds** — each user gets a match threshold measured
  from their own face at enrollment and slowly adapted on successful
  logins; no per-machine tuning.

## Architecture

```
 sudo / GDM / lock / TTY      hiro CLI
         |                      |
      pam_hiro.so                |
         \                      /
          \  Unix socket (SO_PEERCRED)
           v                    v
          +--------------------+
          |      hirod         |  systemd service, runs as root
          |  camera + emitter  |  owns V4L2 IR stream, UVC XU emitter
          |  SCRFD + ArcFace   |  ONNX Runtime, SHA-256-pinned models
          |  SQLite templates  |  AES-256-GCM encrypted embeddings
          |  rate limit + lock |  per-user, with audit log
          +--------------------+
```

Crates: `hiro-core` (config/IPC/embeddings), `hiro-hw` (V4L2 + emitter),
`hiro-face` (ONNX pipeline + stub), `hiro-store` (SQLite),
`hiro-tpm` (key management), `hirod` (daemon), `pam-hiro` (PAM module),
`hiro-cli` (CLI).

## Quick start (Ubuntu/Debian)

```bash
# 1. Build the package
./packaging/build-deb.sh
sudo dpkg -i packaging/hiro_*.deb

# 2. One-time key + database initialization
sudo hirod --init-keys

# 3. Optional but strongly recommended: IR emitter support
#    (GitHub release tarball, not in Ubuntu repos - see docs/hardware.md)
# 4. Download the models and pin their hashes in
#    /usr/share/hiro/models/manifest.toml
sudo /usr/share/hiro/fetch-models.sh

# 5. Sanity checks
sudo hiro doctor      # camera, IR, emitter, models, daemon
sudo systemctl start hirod
hiro status

# 6. Enroll your face (follow the quality hints)
hiro enroll

# 7. Verify before touching PAM
hiro test

# 8. Enable PAM integration (Debian/Ubuntu)
sudo pam-auth-update   # tick "HIRO face authentication"

# 9. Optional: unlock the login keyring automatically on face login
#    (GNOME Keyring / KWallet). Opt in, then store your password once:
#      [keyring] enabled = true   in /etc/hiro/config.toml, then
sudo systemctl restart hirod
hiro keyring set
```

For other distros, see `docs/pam.md`.

## Security model

See `docs/security.md` for the full threat model. Highlights:

- **IR-only**: authentication refuses non-IR cameras (`require_ir = true`).
- **Liveness**: frame variance + landmark micro-motion reject photos and
  screen replays; IR inherently resists displays (they emit little 850 nm).
- **Password after reboot**: like Windows Hello, face auth stays off until
  the account has been logged into since the last reboot
  (`security.require_password_after_boot`, default on). The first login
  must be a password; `pam_hiro.so`'s session hook then arms face auth for
  that user for the rest of the boot.
- **Camera pinning**: templates bind to the enrolling camera's identity.
- **Encrypted at rest**: AES-256-GCM; with a TPM 2.0 present the data key
  is sealed under a TPM primary key (blob in `/var/lib/hiro/hiro.key`),
  otherwise it is a root-only file. Build with `hiro-tpm/tpm` (enabled in
  packaged builds).
- **Constant-time matching** and rate limiting + lockout per user.
- **Action approval**: by default, non-login requests (sudo, lock screen,
  polkit, ...) pause after a confident match for an explicit Allow/Deny
  decision before the action runs; login screens stay instant. The prompt
  can optionally be shown on a dedicated secure console
  (`approval.secure_desktop`). See `docs/security.md`.
- **Audit**: every verdict lands in the journal
  (`journalctl -t hirod -g hiro_audit`) and the events table.

## On-screen scanning indicator

A GNOME Shell extension (`hiro-status@hiro`, installed by the package)
shows an animated indicator while your face is being scanned — a pulsing
camera icon in the top bar plus a centered overlay with a dot animation,
then a green check (with score) or red failure. It works on the desktop,
the lock screen, and anywhere the shell runs. The top-bar icon only
appears while a scan (or its result flash) is on screen and hides when
idle, so it does not look like the camera is in use at all times. When a
non-login request needs approval, the overlay turns into an Allow/Deny
prompt with a live countdown; on the secure console setup it shows a
passive "decide on the secure console" notice instead.

```bash
# system-wide install (via the package) + enable for your session:
sudo dpkg -i packaging/hiro_*.deb   # installs to /usr/share/gnome-shell/extensions
gnome-extensions enable hiro-status@hiro
# or, for just your user:
mkdir -p ~/.local/share/gnome-shell/extensions
cp -r packaging/gnome-shell-extension/hiro-status@hiro ~/.local/share/gnome-shell/extensions/
gnome-extensions enable hiro-status@hiro
# restart the shell (Alt+F2, r) or log out/in to pick up the extension
```

The indicator consumes the daemon's `watch` stream (newline-delimited
`StateEvent` JSON on the existing socket), so any client can drive UI
with it — the extension is just one consumer.

## Hardware support

USB **UVC IR cameras** (the classic Windows Hello module) exposed as V4L2
`/dev/video*` nodes — common on pre-2023 ThinkPads, many Dell/HP/ASUS
laptops. See `docs/hardware.md` for detection guidance.

**Not supported (yet):** Intel IPU6/MIPI cameras (newer ThinkPad Gen 11+,
some XPS models — they need libcamera and the Intel camera HAL) and
RealSense depth cameras.

## Documentation

- `docs/hardware.md` — camera discovery, IR detection, emitter setup
- `docs/security.md` — threat model and hardening notes
- `docs/pam.md` — PAM integration for every distro and service
- `man/hiro.1`, `man/hirod.8`, `man/pam_hiro.8`, `man/hiro.conf.5`

## Development

```bash
cargo test --workspace                 # core, hw, store, daemon e2e (mock camera)
cargo test -p hiro-face --features onnx  # includes ONNX decode/NMS tests
cargo clippy --workspace --all-targets
```

The test suite exercises the full auth path against a deterministic mock
camera and stub pipeline — no hardware needed.

## License

MIT. Model licenses are declared in
`crates/hiro-face/models/manifest.toml` (SCRFD: MIT, AuraFace: Apache-2.0).
