# Security model

HIRO is built as a hardened authenticator, not a convenience unlocker. The
reference bar is Windows Hello: spoof-resistant, IR-based, hardware-bound.

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

### Camera pinning

Enrollment records the camera's USB identity (vendor/product/bus/serial).
Verification on a different camera is refused unless the admin explicitly
sets `security.allow_camera_change` and re-enrolls. This defeats USB
injection attacks against the verification path.

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

### IPC and authorization

- The Unix socket lives at `/run/hirod/hirod.sock`; the daemon verifies
  caller identity via `SO_PEERCRED`.
- A caller may authenticate only for themselves; root may act for anyone
  (greeter workers run as root, lock screens as the user).
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
