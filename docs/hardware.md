# Hardware support and troubleshooting

## Is your camera a UVC IR camera?

Windows Hello laptops ship several camera stacks. HIRO supports **USB UVC
IR cameras** — devices exposed as standard V4L2 nodes under the `uvcvideo`
kernel driver.

Check yours:

```bash
sudo hiro doctor          # prints a per-node breakdown with IR heuristics
v4l2-ctl --list-devices   # raw view, if you prefer
```

Reading `hiro doctor`:

| Signal | Meaning |
| --- | --- |
| `card=...IR Camera...` | Strong IR signal |
| grayscale-only formats (`GRAY`) on one node | Typical IR sensor |
| `driver=ipu6` anywhere | Intel IPU6/MIPI camera — not supported yet |
| Only `Integrated Camera` with YUYV/MJPG | RGB-only webcam |

Typical healthy output looks like:

```
/dev/video0  card=Integrated Camera  driver=uvcvideo  capture=yes  formats=[YUYV, MJPG]
/dev/video2  card=Integrated IR Camera  driver=uvcvideo  capture=yes  IR-CANDIDATE (card name suggests IR)
would use: /dev/video2 (card name suggests IR)
```

If HIRO picks the wrong node, set `device.path` in `/etc/hiro/config.toml`.

## IR emitter

The IR camera needs its 850 nm LED array switched on. HIRO tries, in order:

1. **UVC extension-unit control** for cameras with an entry in
   `/etc/hiro/quirks.toml` (vendor-specific unit/selector/value).
2. **`linux-enable-ir-emitter`**, when installed.

The emitter is lit only while a scan is in progress: it is switched on when
a request starts and switched off as soon as the request finishes. The
camera stream itself stays open for `warm_stream_seconds` between requests
so successive scans start fast, but the IR LEDs are never left glowing
during that idle window.

### Installing linux-enable-ir-emitter (not in Ubuntu repos)

```bash
# From the GitHub release tarball (7.x):
curl -L -o /tmp/ir.tar.gz https://github.com/EmixamPP/linux-enable-ir-emitter/releases/latest/download/linux-enable-ir-emitter-x.x.x-release-x86-64.tar.gz
sudo tar -C /usr/local/bin --no-same-owner -m -vxzf /tmp/ir.tar.gz
# or from source: cargo install linux-enable-ir-emitter

# One-time interactive setup: it probes the camera and records the XU
# tuple that makes the IR LED blink. Answer honestly with yes/no as it
# flashes each candidate.
sudo linux-enable-ir-emitter --device /dev/video2 configure
```

After `configure`, HIRO's emitter fallback runs
`linux-enable-ir-emitter --device <node> run` automatically on each cold
camera start.

If neither works, IR frames stay nearly black and enrollment will time
out. Test directly:

```bash
hiro snapshot /tmp/ir.pgm && magick /tmp/ir.pgm /tmp/ir.png
```

A correct IR frame shows a bright, high-contrast face with the emitter
on. If you discovered working XU values for your camera, add them to
`/etc/hiro/quirks.toml` (schema matches the built-in table) and send a
pull request.

## Camera pinning

Templates are bound to the enrolling camera's USB identity. If you change
laptops (or the camera module is replaced), verification refuses to run
until you re-enroll:

```bash
hiro clear
hiro enroll
```

## Suspend / resume

`hirod-resume.service` restarts the daemon after suspend to re-initialize
the camera, which some laptops lose during sleep.

## Known problem children

- **ThinkPad Gen 11+ / recent XPS**: the integrated camera stack is Intel
  IPU6 (MIPI). These need the Intel camera HAL + libcamera; V4L2 userspace
  does not see them. HIRO support is planned but not implemented.
- **Framework / System76 / Purism**: no IR camera at all — face auth is
  not possible.
- **External USB webcams**: work for smoke tests but are RGB-only, so the
  daemon refuses them for authentication while `require_ir = true`.
