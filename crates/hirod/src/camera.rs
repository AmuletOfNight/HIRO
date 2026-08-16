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

    source: Option<Box<dyn VideoSource>>,
    emitter: Option<Box<dyn Emitter>>,
    streaming: bool,
    emitter_on: bool,
    last_used: Option<Instant>,
    probe: Option<CameraProbe>,
}

impl CameraSession {
    /// Build from configuration. `source` overrides discovery (tests,
    /// custom backends).
    pub fn new(
        cfg: &hiro_core::Config,
        quirks: QuirkDb,
        source: Option<Box<dyn VideoSource>>,
    ) -> Self {
        let mut fourcc = [0u8; 4];
        let pf = cfg.camera.pixel_format.as_bytes();
        fourcc.copy_from_slice(&pf[..4]);
        let mut session = Self {
            device_path: cfg.device.path.clone(),
            width: cfg.camera.width,
            height: cfg.camera.height,
            fps: cfg.camera.fps,
            fourcc,
            require_ir: cfg.device.require_ir,
            emitter_mode: cfg.device.emitter,
            warm_seconds: cfg.device.warm_stream_seconds,
            quirks,
            source,
            emitter: None,
            streaming: false,
            emitter_on: false,
            last_used: None,
            probe: None,
        };
        if session.source.is_none() {
            session.build_from_probe();
        }
        session
    }

    fn build_from_probe(&mut self) {
        let probes = discover::probe_devices();
        let picked = match discover::pick_capture_device(&probes, self.device_path.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("no camera available at startup: {e}");
                return;
            }
        };
        if self.require_ir && !picked.is_ir_candidate {
            log::warn!(
                "configured device {} does not look IR-capable ({})",
                picked.path,
                picked.why_ir
            );
        }
        self.probe = Some(picked.clone());
        match V4lSource::new(&picked.path, self.width, self.height, self.fps, self.fourcc) {
            Ok(src) => self.source = Some(Box::new(src)),
            Err(e) => log::warn!("cannot open camera {}: {e}", picked.path),
        }
    }

    /// Start the stream (and emitter) for a new request. Idempotent; on a
    /// warm resume the stream is already running so this only drains stale
    /// buffered frames and re-lights the emitter.
    pub fn acquire(&mut self) -> HwResult<()> {
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
                // Clear the streaming flag so the next acquire() rebuilds it
                // instead of serving a dead channel (which would fail every
                // request until the idle reaper runs).
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

    fn session_with_fake_emitter(
    ) -> (CameraSession, std::sync::Arc<std::sync::Mutex<usize>>, std::sync::Arc<std::sync::Mutex<usize>>) {
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
            Ok(Some(Frame::new(4, 4, hiro_hw::frame::PixelFormat::Gray8, vec![0u8; 16], 1)))
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
}
