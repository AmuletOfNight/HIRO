# Security model

HIRO ("Hello, InfraRed, On Linux") is built as a hardened authenticator,
not a convenience unlocker. The reference bar is Windows Hello:
spoof-resistant, IR-based, hardware-bound.

## Threat model

Attackers considered:

1. Someone holding your unlocked machine (screen-lock bypass via photos,
   videos, or replay devices).
2. Local unprivileged processes trying to trigger or forge authentications.
3. Offline attackers with the disk (template theft / substitution).
4. Rogue camera hardware (camera swap / injection).

## Controls

### IR-only enforcement

With `device.require_ir = true` (default), the daemon refuses to run
authentication on non-IR nodes. Displays emit almost no 850 nm light, so
screen replays cannot produce a matching IR face image.

### Liveness (anti-spoof)

Two model-free checks run over the capture window and must both pass:

- **Temporal frame variance** — consecutive IR frames of a living subject
  always differ; a static photo produces a constant signal.
- **Landmark micro-motion** — detected facial landmarks jitter and drift
  between frames; a frozen spoof's landmarks are identical.

Thresholds: `recognition.liveness_min_variance` and
`recognition.liveness_min_motion`. A failed gate yields `liveness_failed`
regardless of embedding similarity (no oracle for attackers).

Enrollment does **not** reuse these thresholds. Capturing templates is an
authenticated, interactive operation (the user runs `hiro enroll`), so there
is no photo-replay boundary to defend; requiring motion would just make it
impossible to hold a pose long enough for a sharp, well-framed capture.
Instead, enrollment applies its own quality gates (`min_face_area`,
`min_sharpness`, `dedupe_threshold` for distinct poses, and an optional
`recognition.enroll_min_variance` that defaults to 0 = off). When
`enroll_min_variance` is set above zero, static frames are rejected before
the face pipeline runs, both as a stall guard and as a CPU saving.

`dedupe_threshold` is the "how different must the next pose be" knob, and it
is intentionally lenient by default (0.85): faces of the same person at
modest pose changes score 0.7–0.9 similarity, and even more on IR hardware
due to the RGB→IR domain gap. Raising it makes enrollment accept more frames
at the cost of more redundant templates; lowering it forces larger pose
changes.

### Per-user match-threshold calibration

A single global `match_threshold` is a poor fit across users, cameras, and
lighting: the same person's genuine scores shift with the RGB→IR domain gap
and sensor. With `recognition.auto_threshold` (default on), each user gets
their own threshold:

- **At enrollment**, after templates are captured, a short live pass
  measures the user's genuine match scores against their own templates. The
  stored per-user threshold is the 25th percentile of those scores minus
  `auto_threshold_margin`, clamped to `[auto_threshold_min,
  auto_threshold_max]` (defaults 0.50–0.90). The floor keeps calibration
  from ever demanding *less* than a conservative baseline; the ceiling keeps
  it from requiring scores that real-world captures cannot reach.
- **Adaptive tracking** nudges the threshold toward the observed score of
  each *successful* match at the EMA rate `auto_threshold_adapt` (0.02 =
  slow drift, 0 disables it). Adaptation runs **only on success**: a failed
  attempt — including one crafted by an attacker — never moves the
  threshold, so the calibration cannot be weakened by probing.
- Verification uses the per-user threshold when present, else the global
  `match_threshold`. `hiro test` prints the effective threshold and the best
  score seen so you can observe the drift. Set `auto_threshold = false` to
  fall back to the single global threshold for everyone.

### Camera pinning

Enrollment records a camera **binding**: the USB identity
(vendor/product/bus/serial), the kernel driver, and the canonical sysfs
device path, plus a per-user random pin secret. USB descriptors cannot
influence the driver or sysfs path components, and the pin secret marks
the record as a genuine enrollment. Verification on a different camera —
or against an enrollment that lacks either the binding or the pin secret —
is refused unless the admin explicitly sets `security.allow_camera_change`
and re-enrolls. This defeats USB injection attacks against the
verification path.

Note for upgrades: enrollments created before the pin secret was recorded
are treated as unpinned — verification fails closed (a clean non-match,
password fallback) until the user re-enrolls. Enrollment itself does not
lock the user out: a record without a pin secret is simply re-pinned on
the next `hiro enroll`. `hiro clear` now drops the camera pin along with
the templates, so "clear then re-enroll" always starts fresh.

### Template confidentiality

- Templates are 512-D embeddings; **no images are ever stored**.
- Embeddings are AES-256-GCM encrypted before touching SQLite; the 256-bit
  data key is managed by the `KeyManager` trait (`hiro-tpm`):
  - **TPM 2.0** (packaged builds): the key is sealed under a TPM primary
    key (ECC P-256, storage hierarchy, deterministic template) and stored
    as a TPM2B_PUBLIC + TPM2B_PRIVATE blob — the plaintext key never
    touches disk and unsealing only succeeds on this machine's TPM.
  - **Software fallback**: a root-only keyfile (`/var/lib/hiro/hiro.key`,
    mode 0600), used automatically when no TPM 2.0 is present.
- **Context-bound ciphertexts**: every blob's GCM tag covers the owning
  user name as associated data, so a ciphertext copied into another
  account's row (template substitution by an attacker who can modify the
  database) fails to unseal. The wire format is versioned
  (`0x01 || nonce || ciphertext`); blobs written before this binding are
  **refused on read** — the record reads as undecryptable and the user
  re-enrolls — rather than being accepted in a way that would re-open the
  substitution hole.
- Decryption happens in-memory, per request, in the daemon only.
- Blob format documented in `crates/hiro-tpm/src/tpm.rs`; no PCR binding
  by default (firmware updates must not lock users out), a deliberate
  trade-off versus early-boot integrity pinning.

### Comparison and timing

- Embedding comparisons use constant-time threshold checks
  (`hiro-core::embed::constant_time_match`), so match proximity does not
  leak through timing.
- The reported `score` in audit logs is a deliberate, documented leak kept
  for debuggability; disable via log level if needed.

### Rate limiting and lockout

- Per-user token bucket (default 5 attempts / 60 s).
- Consecutive failures above the threshold trigger a lockout window
  (default 30 s).
- Failures from *any* service (sudo, lock, GDM) share the same counters,
  since the daemon keys by user.
- **Per-user camera budget**: the camera is a single shared device, so a
  user is additionally limited to `security.camera_budget_secs`
  (default 15) of camera-held time per `camera_budget_window_secs`
  (default 60). A single account cannot monopolise the camera and block
  every other user's face auth by chaining verify/enroll requests. The
  action-approval phase (which runs only after a real face match) is
  exempt.

### IPC and authorization

- The Unix socket lives at `/run/hirod/hirod.sock`; the daemon verifies
  caller identity via `SO_PEERCRED`.
- A caller may authenticate only for themselves; root may act for anyone
  (greeter workers run as root, lock screens as the user).
- Administrative operations are root-only: `reload` (re-reads
  configuration and can rebuild the recognition pipeline) and `prewarm`
  (acquires the camera / toggles the IR emitter).
- `watch` streams are filtered by caller: root sees all events, everyone
  else only their own user's, so no local process can monitor other
  users' authentication activity.
- The daemon is the only component that touches the camera, models, key,
  and templates.

### Daemon hardening (systemd)

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`RestrictAddressFamilies=AF_UNIX` (no network), `DeviceAllow` limited to
video4linux/usb character devices, `MemoryDenyWriteExecute`,
`SystemCallArchitectures=native`.

### Fail-closed PAM semantics

`pam_hiro.so` maps every failure to password fallback
(`PAM_AUTH_ERR` / `PAM_AUTHINFO_UNAVAIL`); a face mismatch can never
block login, and the module itself performs no recognition.

### Action approval gate

By default, a confident face match only *authorizes* a request after the
user explicitly allows it. This closes the "face scan happens in the
background" hole: a site or process asking for `sudo` should not run
silently just because the camera recognizes the user.

- `approval.enabled` (default **true**) gates every service except
  `approval.bypass_services` (default: graphical greeters / session
  logins and `hiro test`). Login screens stay instant because the user
  triggers them themselves.
- On a match, `hirod` broadcasts `state: "approval_pending"` with the
  requesting service, the match score, and an `approval_id`. The status
  indicator shows **Allow** / **Deny**; the decision is sent back via the
  `approve` IPC op, authorized to the target user (or root) only.
- The request is **denied** only when the decision window
  (`approval.timeout_ms`, default 5 s) expires, or when the user clicks
  **Deny**. Stepping out of the frame is *not* a failure: after
  `approval.absent_frames` consecutive frames with no convincing face
  (`approval.absent_score_margin` below the effective match threshold),
  the buttons disappear, but the request keeps waiting — the prompt
  returns if the user steps back into the frame, and the request still
  only fails when the window actually times out. The default debounce
  (~30 frames ≈ 1 s at 30 fps) also stops a momentary detection blip from
  hiding the prompt.
- Verdicts are audited (`reason=approved|approval_denied|
  approval_timeout`) and, like any non-match, count toward the per-user
  failure/rate-limit counters.
- With `approval.secure_desktop = true` (default **off**), the prompt is
  rendered by the `hiro-approve` helper on a dedicated VT ("secure
  console") instead of the in-session indicator, so a compromised user
  session cannot fake or overlay the dialog. The daemon spawns the helper
  outside its hardened unit via `systemd-run` (direct spawn as fallback),
  which requires root and a VT console; the helper switches to the
  configured VT (`approval.secure_vt`, default 8), shows a centered,
  full-screen Allow/Deny prompt with large block-letter keys (Enter/Y or
  Esc/N/Q) and a big countdown, sends the decision, and returns to the
  previous VT. As with the in-session prompt, the dialog dismisses itself
  when the daemon reports the user stepped away (`user_present: false`);
  `hirod` re-opens it if the user steps back into the frame before the
  window expires.
- The secure-console decision is **root-gated**: each secure approval gets
  a fresh random secret that only `hirod` and the spawned root-owned
  `hiro-approve` dialog know, and `Op::Approve` is honoured only when the
  caller is root *and* presents that secret. A compromised session — even
  one that can watch the approval events — cannot decide; it can only see
  the prompt and wait. The secret is delivered to the dialog through a
  root-only file (mode 0600, unlinked after read) rather than its command
  line — a root process's argv is world-readable on default Linux
  (`/proc/<pid>/cmdline` is 0444 without `hidepid`), and `systemd-run`
  records the ExecStart line, so argv would leak the secret to any local
  process. With the in-session prompt (`secure_desktop` off), the decision
  lives in the user's session by design, so any process running as that
  user can click Allow — that is inherent to rendering the prompt in the
  session, and is why `secure_desktop` exists for the strong guarantee.

### After-reboot password gate

Like Windows Hello and macOS Touch ID, HIRO refuses face authentication
until the account has been logged into since the last reboot
(`security.require_password_after_boot`, default on):

- After boot, `hirod` refuses to verify **or enroll** any user whose login
  it has not seen during the current boot. The verdict is a clean
  non-match (`reason=password_required`, camera untouched), so the PAM
  stack simply falls through to the password prompt.
- The first login of a boot necessarily happens through the password (or
  another non-HIRO method such as auto-login/`nopasswdlogin`/SSH key).
  `pam_hiro.so` reports that login from its session hook (`Op::Login`,
  installed as `optional pam_hiro.so` in the session stack), arming face
  auth for that user for the rest of the boot.
- State is persisted in SQLite keyed by the kernel boot id
  (`/proc/sys/kernel/random/boot_id`), so daemon restarts mid-boot
  (suspend/resume, crashes) do not reset it; a real reboot prunes it.
- Arming is **root-only**: `Op::Login` is honoured only for root callers,
  which is who the greeter/login PAM session hooks run as. A process
  running as the user can never arm face auth for an account, so the gate
  cannot be silently bypassed by malware in a session.
- Trade-off: anyone able to establish a session for a user during a boot
  (e.g. root, or passwordless/auto-login configured by the administrator)
  arms that user's face auth without a typed password. That matches the
  intent — the gate exists so a stolen, freshly-booted laptop cannot be
  unlocked by face — and passwordless login is an explicit admin choice.

### Keyring unlock (optional)

With `[keyring] enabled = true` the user may seal their login password
(`hiro keyring set`) so face login unlocks the login keyring. Control flow
and mitigations:

- The password is stored only as AES-256-GCM ciphertext under the same
  TPM-sealed data key that protects templates (see above); plaintext never
  touches disk.
- On every face match, `hirod` re-verifies the password against
  `/etc/shadow` (`crypt_r`, `getspnam_r` — thread-safe, constant-time
  compare) *before* releasing it to `pam_hiro.so`. A stale or mistyped
  secret is never released, so a changed password cannot break face login;
  it only leaves the keyring locked until the user re-enrolls.
- The password is released only when the caller is **root** (greeter and
  login stacks run as root), the face matched, the service is listed in
  `keyring.services`, and the client asked for it (`pam_hiro.so keyring`).
  Restricting release to root closes the silent-harvesting hole where a
  process running as the user could ask for the login password and receive
  it the moment the user's face was in front of the camera — the daemon
  cannot distinguish a real greeter from same-uid malware, so same-uid
  callers never receive it.
- Release and refusal are both audited (`keyring_unlock` events).
- Trade-off: anyone who can pass face auth for a user can unlock that
  user's keyring. That is the feature's purpose; disabling `[keyring]`
  restores the default behavior (face login, keyring stays locked).

### Supply chain

- Model files are pinned by SHA-256 in the manifest and re-verified at
  every daemon start (`hiro doctor` checks them too).
- No runtime network access: the daemon cannot phone home (systemd
  `RestrictAddressFamilies`), and the ONNX runtime runs fully offline.

## Residual risks

- **RGB→IR domain gap**: models are RGB-trained; on unusual IR hardware the
  threshold may need calibration. Mitigation: quality-gated enrollment and
  per-user `match_threshold`.
- **Software key storage (no TPM)**: without a TPM the AES key rests on
  disk root-only; an attacker with root defeats everything (true for any
  biometric stack without a TPM).
- **No PCR binding**: the sealed key is not bound to firmware/early-boot
  measurements, so it does not protect against a compromised root from
  *before* the daemon starts. Binding to PCR 0+7 (or a policy with
  `TPM2_PolicySigned`) is the next hardening step.
- **No template revocation secret**: deleting templates (`hiro clear`)
  fully removes them; there is nothing to rotate.
