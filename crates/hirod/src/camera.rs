//! Camera session management: owns the video source and IR emitter,
//! keeps the stream warm between rapid requests, and reaps it when idle.

use std::time::{Duration, Instant};

use hiro_core::{proto::CameraProbe, CameraIdentity};
use hiro_hw::capture::{V4lSource, VideoSource};
use hiro_hw::emitter::{build_emitter, Emitter};
use hiro_hw::frame::Frame;
use hiro_hw::{discover, quirks::QuirkDb, HwError, HwResult};

pub struct CameraSession {
    device_path: Option<String>,
    width: u32,
    height: u32,
    fps: u32,
    fourcc: [u8; 4],
    require_ir: bool,
    emitter_mode: hiro_core::config::EmitterMode,
    warm_seconds: u64,
    quirks: QuirkDb,

    /// How the camera is discovered and opened. `preferred` is the
    /// configured `device.path`; the production implementation enumerates
    /// `/dev/video*` and opens the picked node as a V4L2 mmap source.
    /// Tests inject a stub so hotplug recovery can be exercised without
    /// hardware. See [`real_discovery`].
    discovery: Discovery,

    source: Option<Box<dyn VideoSource>>,
    emitter: Option<Box<dyn Emitter>>,
    streaming: bool,
    emitter_on: bool,
    last_used: Option<Instant>,
    probe: Option<CameraProbe>,
}

/// Discovers and opens a camera: given the preferred configured path (if
/// any) and the capture geometry, return the picked probe and a
/// ready-to-stream source.
type Discovery = Box<
    dyn FnMut(&Option<String>, u32, u32, u32, [u8; 4]) -> HwResult<(CameraProbe, Box<dyn VideoSource>)>
        + Send,
>;

/// Production camera discovery: enumerate `/dev/video*`, pick the best
/// capture device (honouring a configured preferred path), and open it as a
/// V4L2 mmap source.
fn real_discovery(
    preferred: &Option<String>,
    width: u32,
    height: u32,
    fps: u32,
    fourcc: [u8; 4],
) -> HwResult<(CameraProbe, Box<dyn VideoSource>)> {
    let probes = discover::probe_devices();
    let picked = discover::pick_capture_device(&probes, preferred.as_deref())?;
    let source: Box<dyn VideoSource> =
        Box::new(V4lSource::new(&picked.path, width, height, fps, fourcc)?);
    Ok((picked, source))
}

impl CameraSession {
    /// Build from configuration. `source` overrides discovery (tests,
    /// custom backends).
    pub fn new(
        cfg: &hiro_core::Config,
        quirks: QuirkDb,
        source: Option<Box<dyn VideoSource>>,
    ) -> Self {
        let mut session = Self::with_discovery(cfg, quirks, source, Box::new(real_discovery));
        if session.source.is_none() {
            if let Err(e) = session.build_from_probe() {
                log::warn!("no camera available at startup: {e}");
            }
        }
        session
    }

    /// Constructor with an explicit discovery strategy. Produces the same
    /// session as [`Self::new`] but runs `discovery` instead of the real
    /// `/dev/video*` enumeration whenever a (re)probe happens; used by
    /// tests to simulate hotplugs deterministically.
    fn with_discovery(
        cfg: &hiro_core::Config,
        quirks: QuirkDb,
        source: Option<Box<dyn VideoSource>>,
        discovery: Discovery,
    ) -> Self {
        let mut fourcc = [0u8; 4];
        let pf = cfg.camera.pixel_format.as_bytes();
        fourcc.copy_from_slice(&pf[..4]);
        Self {
            device_path: cfg.device.path.clone(),
            width: cfg.camera.width,
            height: cfg.camera.height,
            fps: cfg.camera.fps,
            fourcc,
            require_ir: cfg.device.require_ir,
            emitter_mode: cfg.device.emitter,
            warm_seconds: cfg.device.warm_stream_seconds,
            quirks,
            discovery,
            source,
            emitter: None,
            streaming: false,
            emitter_on: false,
            last_used: None,
            probe: None,
        }
    }

    fn build_from_probe(&mut self) -> HwResult<()> {
        let discovery = &mut self.discovery;
        let (picked, source) = discovery(
            &self.device_path,
            self.width,
            self.height,
            self.fps,
            self.fourcc,
        )?;
        if self.require_ir && !picked.is_ir_candidate {
            // Hard refusal, not a warning: the IR-only rule is the primary
            // anti-screen-replay control. A non-IR node must never serve
            // authentication; the session is left without a source so every
            // acquire() fails cleanly (camera_unavailable, password fallback).
            log::error!(
                "refusing to use {} for authentication: require_ir is set but the device \
                 is not IR-capable ({})",
                picked.path,
                picked.why_ir
            );
            self.probe = Some(picked);
            return Err(HwError::NoCamera);
        }
        self.probe = Some(picked);
        self.source = Some(source);
        Ok(())
    }

    /// Drop the current source and re-discover the camera from scratch.
    ///
    /// Re-picks the capture device rather than re-opening the previous
    /// node, because a camera that was unplugged and re-plugged (KVM
    /// switch, suspend/resume, USB re-enumeration) can return on a
    /// different `/dev/videoN`. Called from [`Self::acquire`] whenever there
    /// is no source or the current source's capture thread has died.
    fn rebuild_source(&mut self) -> HwResult<()> {
        // Tear down anything tied to the old device before probing again.
        if let Some(src) = self.source.as_mut() {
            src.stop();
        }
        self.source = None;
        self.emitter = None;
        self.streaming = false;
        self.emitter_on = false;
        self.last_used = None;
        self.probe = None;
        self.build_from_probe()
    }

    /// Start the stream (and emitter) for a new request. Idempotent; on a
    /// warm resume the stream is already running so this only drains stale
    /// buffered frames and re-lights the emitter.
    ///
    /// Self-heals across camera hotplugs: if there is no source (the camera
    /// was absent when the daemon started) or the current source's capture
    /// thread has exited (the camera was unplugged, possibly returning at a
    /// different `/dev/videoN` node), the camera is re-discovered and
    /// re-opened before this request is served. The re-probe only runs when
    /// something is actually wrong, so the common cold/warm path is
    /// unchanged.
    pub fn acquire(&mut self) -> HwResult<()> {
        if !self.source.as_ref().is_some_and(|s| s.is_alive()) {
            self.rebuild_source()?;
        }
        if !self.streaming {
            self.source.as_mut().ok_or(HwError::NoCamera)?.start()?;
            self.streaming = true;
        }
        // Drop any frames buffered while the stream sat warm, so this
        // request only ever sees frames captured after it began. Without
        // this, a quick follow-up request (e.g. `hiro test` right after a
        // match) can be decided on stale frames that still show the user's
        // face from the previous attempt.
        if let Some(src) = self.source.as_mut() {
            src.drain();
        }
        // Light the IR emitter for this request, whether it is a cold start
        // or a warm resume after release() switched it off.
        if !self.emitter_on {
            if let Some(mut emitter) = self.take_emitter() {
                match emitter.enable() {
                    Ok(active) => {
                        self.emitter_on = active;
                        log::info!("IR emitter on ({active})");
                    }
                    Err(e) => log::warn!("cannot enable IR emitter: {e}"),
                }
                self.emitter = Some(emitter);
            }
        }
        self.last_used = Some(Instant::now());
        Ok(())
    }

    fn take_emitter(&mut self) -> Option<Box<dyn Emitter>> {
        if let Some(e) = self.emitter.take() {
            return Some(e);
        }
        let path = self
            .probe
            .as_ref()
            .map(|p| p.path.clone())
            .unwrap_or_else(|| "/dev/video0".into());
        let identity = self
            .source
            .as_ref()
            .map(|s| s.identity())
            .unwrap_or_default();
        build_emitter(self.emitter_mode, path, identity, self.quirks.clone())
    }

    pub fn next_frame(&mut self, timeout: Duration) -> HwResult<Option<Frame>> {
        let source = self.source.as_mut().ok_or(HwError::NoCamera)?;
        match source.next_frame(timeout) {
            Ok(frame) => Ok(frame),
            Err(e) => {
                // The capture thread died; the source can no longer stream.
                // Leave the (dead) source in place but mark the session not
                // streaming: the next acquire() sees the source reports not
                // alive (disconnected channel) and rebuilds it from a fresh
                // probe, which also re-discovers the camera in case it
                // returned at a different /dev/videoN node.
                self.streaming = false;
                self.last_used = None;
                Err(e)
            }
        }
    }

    /// Mark the session idle. The stream stays warm for the warm window so
    /// the next request starts fast, but the IR emitter is switched off
    /// immediately instead of glowing for the whole window; the next
    /// `acquire()` re-lights it.
    pub fn release(&mut self) {
        self.last_used = Some(Instant::now());
        if self.emitter_on {
            if let Some(emitter) = self.emitter.as_mut() {
                emitter.disable();
            }
            self.emitter_on = false;
        }
    }

    /// Close the stream and emitter when idle past the warm window.
    pub fn reap_if_idle(&mut self) {
        let idle_for = self.last_used.map(|t| t.elapsed()).unwrap_or_default();
        if self.streaming && idle_for > Duration::from_secs(self.warm_seconds) {
            log::info!("camera idle for {}s, releasing stream", idle_for.as_secs());
            self.close();
        }
    }

    pub fn close(&mut self) {
        if let Some(src) = self.source.as_mut() {
            src.stop();
        }
        if self.emitter_on {
            if let Some(emitter) = self.emitter.as_mut() {
                emitter.disable();
            }
            self.emitter_on = false;
        }
        self.streaming = false;
        self.last_used = None;
    }

    pub fn identity(&self) -> Option<CameraIdentity> {
        self.probe
            .as_ref()
            .map(|p| p.identity.clone())
            .or_else(|| self.source.as_ref().map(|s| s.identity()))
    }

    pub fn is_ir_candidate(&self) -> Option<bool> {
        self.probe.as_ref().map(|p| p.is_ir_candidate)
    }

    pub fn camera_path(&self) -> Option<String> {
        self.probe.as_ref().map(|p| p.path.clone())
    }

    pub fn driver(&self) -> Option<String> {
        self.probe.as_ref().and_then(|p| p.driver.clone())
    }

    pub fn streaming(&self) -> bool {
        self.streaming
    }

    /// Whether the IR emitter is currently lit. Decoupled from the stream:
    /// the stream stays warm between requests, but the emitter is switched
    /// off once a request finishes.
    pub fn emitter_active(&self) -> bool {
        self.emitter_on
    }

    pub fn describe(&self) -> String {
        match &self.source {
            Some(s) => s.describe(),
            None => "no camera".into(),
        }
    }

    /// Test/dev helper: reconfigure the mock source's face schedule.
    pub fn set_mock_face_every(&mut self, every: Option<u32>) {
        if let Some(src) = self.source.as_mut() {
            if let Some(any) = src.as_any_mut() {
                if let Some(mock) = any.downcast_mut::<hiro_hw::mock::MockSource>() {
                    mock.face_every = every;
                    mock.face_frames.clear();
                }
            }
        }
    }
}

/// Background reaper thread: closes the camera stream after idle. Polls
/// `shutdown` and exits when it is set, so the daemon can join it on
/// SIGTERM/SIGINT instead of hanging forever.
pub fn spawn_reaper(
    camera: std::sync::Arc<std::sync::Mutex<CameraSession>>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    std::thread::Builder::new()
        .name("hiro-camera-reaper".into())
        .spawn(move || loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let mut cam = match camera.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            cam.reap_if_idle();
        })
        .expect("spawn reaper thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiro_core::config::Config;
    use hiro_hw::mock::MockSource;
    use hiro_hw::quirks::QuirkDb;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Fake emitter that counts enable/disable calls so tests can observe
    /// the session's IR lifecycle.
    struct FakeEmitter {
        enabled: std::sync::Arc<std::sync::Mutex<usize>>,
        disabled: std::sync::Arc<std::sync::Mutex<usize>>,
    }

    impl Emitter for FakeEmitter {
        fn enable(&mut self) -> HwResult<bool> {
            *self.enabled.lock().unwrap() += 1;
            Ok(true)
        }
        fn disable(&mut self) {
            *self.disabled.lock().unwrap() += 1;
        }
    }

    fn session_with_fake_emitter() -> (
        CameraSession,
        std::sync::Arc<std::sync::Mutex<usize>>,
        std::sync::Arc<std::sync::Mutex<usize>>,
    ) {
        let mut cfg = Config::default();
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;
        let mut cam = CameraSession::new(
            &cfg,
            QuirkDb::default(),
            Some(Box::new(MockSource::new(64, 48, vec![]))),
        );
        let enabled = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let disabled = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        cam.emitter = Some(Box::new(FakeEmitter {
            enabled: enabled.clone(),
            disabled: disabled.clone(),
        }));
        (cam, enabled, disabled)
    }

    #[test]
    fn emitter_off_on_release_and_back_on_warm_resume() {
        let (mut cam, enabled, disabled) = session_with_fake_emitter();

        // Cold start lights the emitter.
        cam.acquire().unwrap();
        assert!(cam.emitter_on);
        assert_eq!(*enabled.lock().unwrap(), 1);

        // Another acquire while warm must not re-enable it.
        cam.acquire().unwrap();
        assert!(cam.emitter_on);
        assert_eq!(*enabled.lock().unwrap(), 1);

        // Release turns the IR off immediately but keeps the stream warm.
        cam.release();
        assert!(!cam.emitter_on);
        assert_eq!(*disabled.lock().unwrap(), 1);
        assert!(cam.streaming());

        // Warm resume re-lights the emitter (same object, no rebuild).
        cam.acquire().unwrap();
        assert!(cam.emitter_on);
        assert_eq!(*enabled.lock().unwrap(), 2);

        // close() disables the on emitter exactly once.
        cam.close();
        assert!(!cam.streaming());
        assert!(!cam.emitter_on);
        assert_eq!(*disabled.lock().unwrap(), 2);

        // A second close after release must not disable again.
        cam.close();
        assert_eq!(*disabled.lock().unwrap(), 2);
    }

    #[test]
    fn emitter_off_after_release_before_warm_window_expires() {
        let (mut cam, enabled, disabled) = session_with_fake_emitter();
        cam.acquire().unwrap();
        assert!(cam.emitter_on);

        // Simulate a finished request: release happens now, and the reaper
        // would only close the session after warm_stream_seconds. The
        // emitter must not stay lit for that whole window.
        cam.release();
        assert!(!cam.emitter_on, "IR must be off immediately after release");
        assert_eq!(*enabled.lock().unwrap(), 1);
        assert_eq!(*disabled.lock().unwrap(), 1);
    }

    /// VideoSource that behaves like V4lSource while warm: it buffers up to
    /// `buffered` stale frames (the bounded capture channel) and records
    /// drain calls.
    struct BufferedSource {
        buffered: usize,
        drain_calls: std::sync::Arc<std::sync::Mutex<usize>>,
        started: bool,
    }

    impl VideoSource for BufferedSource {
        fn start(&mut self) -> HwResult<()> {
            self.started = true;
            Ok(())
        }
        fn next_frame(&mut self, _timeout: Duration) -> HwResult<Option<Frame>> {
            if !self.started {
                return Ok(None);
            }
            Ok(Some(Frame::new(
                4,
                4,
                hiro_hw::frame::PixelFormat::Gray8,
                vec![0u8; 16],
                1,
            )))
        }
        fn stop(&mut self) {
            self.started = false;
        }
        fn drain(&mut self) {
            self.buffered = 0;
            *self.drain_calls.lock().unwrap() += 1;
        }
        fn identity(&self) -> hiro_core::CameraIdentity {
            hiro_core::CameraIdentity {
                vendor_id: Some(0xFFFF),
                product_id: Some(0x0002),
                bus_info: Some("buffered".into()),
                serial: None,
            }
        }
        fn describe(&self) -> String {
            "buffered".into()
        }
        fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
            Some(self)
        }
    }

    #[test]
    fn acquire_drains_stale_frames_every_request() {
        let mut cfg = Config::default();
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;
        let drain_calls = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let mut cam = CameraSession::new(
            &cfg,
            QuirkDb::default(),
            Some(Box::new(BufferedSource {
                buffered: 4,
                drain_calls: drain_calls.clone(),
                started: false,
            })),
        );

        // Cold start: the fresh channel is empty, drain is a cheap no-op.
        cam.acquire().unwrap();
        assert_eq!(*drain_calls.lock().unwrap(), 1);

        // Simulate the capture thread buffering stale frames while the
        // stream sat warm, then a follow-up request arriving.
        {
            let src = cam
                .source
                .as_mut()
                .unwrap()
                .as_any_mut()
                .unwrap()
                .downcast_mut::<BufferedSource>()
                .unwrap();
            src.buffered = 4;
        }
        cam.acquire().unwrap();
        assert_eq!(*drain_calls.lock().unwrap(), 2);
        {
            let src = cam
                .source
                .as_mut()
                .unwrap()
                .as_any_mut()
                .unwrap()
                .downcast_mut::<BufferedSource>()
                .unwrap();
            assert_eq!(src.buffered, 0, "stale frames must be drained");
        }
    }

    /// A plausible discovery result for a (fake) IR camera on /dev/video0.
    fn fake_probe() -> CameraProbe {
        CameraProbe {
            path: "/dev/video0".into(),
            driver: Some("uvcvideo".into()),
            card: Some("Fake IR Camera".into()),
            bus_info: Some("usb-fake".into()),
            identity: CameraIdentity::default(),
            is_ir_candidate: true,
            why_ir: String::new(),
            captures_video: true,
            formats: vec![],
        }
    }

    /// VideoSource that can be flagged dead (simulating a capture thread
    /// that exited after the camera was unplugged) while otherwise behaving
    /// like a mock. The session must detect `is_alive() == false` and
    /// rebuild the source from a fresh probe.
    struct FlakySource {
        inner: MockSource,
        dead: Arc<AtomicBool>,
        fail_start: Arc<AtomicBool>,
    }

    impl VideoSource for FlakySource {
        fn start(&mut self) -> HwResult<()> {
            if self.fail_start.load(Ordering::SeqCst) {
                // Mimic V4lSource::start(): an open failure marks the
                // source dead so the session rebuilds it on the next
                // acquire instead of retrying the stale path.
                self.dead.store(true, Ordering::SeqCst);
                return Err(HwError::Camera("node vanished before stream open".into()));
            }
            self.inner.start()
        }
        fn next_frame(&mut self, timeout: Duration) -> HwResult<Option<Frame>> {
            self.inner.next_frame(timeout)
        }
        fn stop(&mut self) {
            self.inner.stop();
        }
        fn is_alive(&self) -> bool {
            !self.dead.load(Ordering::SeqCst)
        }
        fn identity(&self) -> hiro_core::CameraIdentity {
            self.inner.identity()
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
        fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
            Some(self)
        }
    }

    /// A session whose startup/acquire is driven by a controllable fake
    /// camera that can be absent or present.
    fn hotplug_session(
        present: &Arc<AtomicBool>,
        discovers: &Arc<std::sync::Mutex<usize>>,
    ) -> CameraSession {
        let mut cfg = Config::default();
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;
        // Keep the emitter out of these tests: an Auto emitter would try to
        // poke the real /dev/video0 when the fake probe is used.
        cfg.device.emitter = hiro_core::config::EmitterMode::Off;
        let present = present.clone();
        let discovers = discovers.clone();
        CameraSession::with_discovery(
            &cfg,
            QuirkDb::default(),
            None,
            Box::new(move |_pref, width, height, _fps, _fourcc| {
                *discovers.lock().unwrap() += 1;
                if !present.load(Ordering::SeqCst) {
                    return Err(HwError::NoCamera);
                }
                Ok((
                    fake_probe(),
                    Box::new(MockSource::new(width, height, vec![])),
                ))
            }),
        )
    }

    #[test]
    fn acquire_reprobes_when_camera_returns_after_absent_startup() {
        // The daemon started while the camera was absent (e.g. a KVM switch
        // pointed it at another machine during suspend/resume), so the
        // session has no source. Once the camera is plugged back in, the
        // very next acquire() must re-discover it instead of permanently
        // reporting camera_unavailable.
        let present = Arc::new(AtomicBool::new(false));
        let discovers = Arc::new(std::sync::Mutex::new(0usize));
        let mut cam = hotplug_session(&present, &discovers);

        // Absent: acquire fails cleanly and leaves no source behind.
        assert!(cam.acquire().is_err());
        assert!(cam.camera_path().is_none());

        // The camera comes back: acquire re-probes and streams.
        present.store(true, Ordering::SeqCst);
        cam.acquire().unwrap();
        assert_eq!(cam.camera_path().as_deref(), Some("/dev/video0"));
        assert!(cam.streaming());
        assert!(cam.next_frame(Duration::from_millis(10)).unwrap().is_some());
    }

    #[test]
    fn acquire_rebuilds_source_after_capture_thread_dies() {
        // A camera that was streaming is unplugged mid-session: the capture
        // thread exits and the source reports not alive. The next acquire()
        // must drop the stale source (pinned to the old node) and rebuild
        // from a fresh probe.
        let discovers = Arc::new(std::sync::Mutex::new(0usize));
        let mut cfg = Config::default();
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;
        cfg.device.emitter = hiro_core::config::EmitterMode::Off;
        let dead = Arc::new(AtomicBool::new(false));
        let dead_in_disc = dead.clone();
        let discovers_in_disc = discovers.clone();
        let fail_start = Arc::new(AtomicBool::new(false));
        let fail_start_in_disc = fail_start.clone();
        let mut cam = CameraSession::with_discovery(
            &cfg,
            QuirkDb::default(),
            None,
            Box::new(move |_pref, width, height, _fps, _fourcc| {
                *discovers_in_disc.lock().unwrap() += 1;
                // A freshly discovered camera is alive; only the test flips
                // the flag to simulate an unplug.
                dead_in_disc.store(false, Ordering::SeqCst);
                Ok((
                    fake_probe(),
                    Box::new(FlakySource {
                        inner: MockSource::new(width, height, vec![]),
                        dead: dead_in_disc.clone(),
                        fail_start: fail_start_in_disc.clone(),
                    }),
                ))
            }),
        );

        cam.acquire().unwrap();
        assert_eq!(*discovers.lock().unwrap(), 1);

        // The camera is unplugged: the capture thread dies.
        dead.store(true, Ordering::SeqCst);

        // The next acquire notices the dead source, re-probes, and opens a
        // fresh source that streams again.
        cam.acquire().unwrap();
        assert_eq!(*discovers.lock().unwrap(), 2, "dead source must trigger a re-probe");
        assert!(cam.streaming());
        assert!(cam.next_frame(Duration::from_millis(10)).unwrap().is_some());
    }

    #[test]
    fn acquire_rebuilds_after_start_failure_invalidates_source() {
        // The camera vanished between discovery and stream open (a race):
        // the first start() fails and, like V4lSource, marks the source
        // dead. The next acquire must re-discover instead of retrying the
        // stale path forever — including when the camera returned at a new
        // node.
        let discovers = Arc::new(std::sync::Mutex::new(0usize));
        let mut cfg = Config::default();
        cfg.camera.width = 64;
        cfg.camera.height = 48;
        cfg.device.require_ir = false;
        cfg.device.emitter = hiro_core::config::EmitterMode::Off;
        let dead = Arc::new(AtomicBool::new(false));
        let dead_in_disc = dead.clone();
        let discovers_in_disc = discovers.clone();
        let fail_start = Arc::new(AtomicBool::new(true));
        let fail_start_in_disc = fail_start.clone();
        let mut cam = CameraSession::with_discovery(
            &cfg,
            QuirkDb::default(),
            None,
            Box::new(move |_pref, width, height, _fps, _fourcc| {
                *discovers_in_disc.lock().unwrap() += 1;
                // Each fresh source starts alive; whether its start() then
                // fails is controlled by the test through `fail_start`.
                dead_in_disc.store(false, Ordering::SeqCst);
                Ok((
                    fake_probe(),
                    Box::new(FlakySource {
                        inner: MockSource::new(width, height, vec![]),
                        dead: dead_in_disc.clone(),
                        fail_start: fail_start_in_disc.clone(),
                    }),
                ))
            }),
        );

        // Discovery found a camera but opening it fails: acquire errors and
        // the source invalidates itself.
        assert!(cam.acquire().is_err());

        // The camera is reachable again: the dead source triggers a fresh
        // probe, which streams.
        fail_start.store(false, Ordering::SeqCst);
        cam.acquire().unwrap();
        assert_eq!(
            *discovers.lock().unwrap(),
            2,
            "a start failure must lead to a re-probe, not stale-path retries"
        );
        assert!(cam.streaming());
        assert!(cam.next_frame(Duration::from_millis(10)).unwrap().is_some());
    }

    #[test]
    fn healthy_session_does_not_reprobe_on_every_acquire() {
        // The self-heal must not degrade the common path: a live source is
        // re-used across warm resumes and release/close cycles without
        // re-scanning /dev every time.
        let present = Arc::new(AtomicBool::new(true));
        let discovers = Arc::new(std::sync::Mutex::new(0usize));
        let mut cam = hotplug_session(&present, &discovers);

        cam.acquire().unwrap();
        assert_eq!(*discovers.lock().unwrap(), 1);

        cam.acquire().unwrap();
        cam.release();
        cam.acquire().unwrap();
        cam.close();
        cam.acquire().unwrap();
        assert_eq!(
            *discovers.lock().unwrap(),
            1,
            "a healthy session must never re-discover"
        );
    }
}
