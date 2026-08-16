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

    /// Start the stream (and emitter, on a cold start). Idempotent.
    pub fn acquire(&mut self) -> HwResult<()> {
        if self.streaming {
            self.last_used = Some(Instant::now());
            return Ok(());
        }
        self.source.as_mut().ok_or(HwError::NoCamera)?.start()?;
        self.streaming = true;
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
        source.next_frame(timeout)
    }

    /// Mark the session idle; the reaper closes it after the warm period.
    pub fn release(&mut self) {
        self.last_used = Some(Instant::now());
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
        if let Some(emitter) = self.emitter.as_mut() {
            emitter.disable();
        }
        self.streaming = false;
        self.emitter_on = false;
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

/// Background reaper thread: closes the camera stream after idle.
pub fn spawn_reaper(
    camera: std::sync::Arc<std::sync::Mutex<CameraSession>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("hiro-camera-reaper".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let mut cam = match camera.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            cam.reap_if_idle();
        })
        .expect("spawn reaper thread")
}
