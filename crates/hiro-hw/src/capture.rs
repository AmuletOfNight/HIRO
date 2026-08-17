//! V4L2 capture behind a [`VideoSource`] abstraction.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use hiro_core::CameraIdentity;
use v4l::buffer::Type;
use v4l::io::traits::{CaptureStream, Stream as StreamTrait};
use v4l::prelude::*;
use v4l::video::capture::Parameters;
use v4l::video::traits::Capture;
use v4l::{Device, Format, FourCC};

use crate::frame::{Frame, PixelFormat};
use crate::HwResult;
use crate::{discover, HwError};

/// A stream of video frames from some source (real camera or mock).
pub trait VideoSource: Send {
    /// Begin streaming. Idempotent.
    fn start(&mut self) -> HwResult<()>;
    /// Wait up to `timeout` for the next frame; `Ok(None)` on timeout.
    fn next_frame(&mut self, timeout: Duration) -> HwResult<Option<Frame>>;
    /// Stop streaming and release the device.
    fn stop(&mut self);
    fn identity(&self) -> CameraIdentity;
    fn describe(&self) -> String;
    /// Test/dev escape hatch: downcast to a concrete implementation.
    /// Real sources return `None`; mocks return themselves.
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
    /// Discard any frames buffered while the stream sat warm between
    /// requests. A new request must only ever see frames captured after it
    /// began; buffered frames can be stale (for example, the user has
    /// already turned away by the time the next request arrives). The
    /// default implementation does nothing.
    fn drain(&mut self) {}

    /// Whether the source can still deliver frames.
    ///
    /// The default `true` is correct for sources without an internal thread
    /// (mocks). The V4L2 implementation overrides this so the camera
    /// session can detect a capture thread that exited when the device was
    /// unplugged (or killed by an I/O error) and rebuild itself from a
    /// fresh probe instead of serving a dead channel forever.
    fn is_alive(&self) -> bool {
        true
    }
}

/// mmap-streaming V4L2 source. Capture runs on a dedicated thread; frames
/// are delivered through a small bounded channel so request handling never
/// blocks on camera I/O.
pub struct V4lSource {
    path: PathBuf,
    width: u32,
    height: u32,
    fps: u32,
    fourcc: [u8; 4],
    identity: CameraIdentity,
    control: Option<SyncSender<()>>,
    frames: Option<Receiver<Frame>>,
    started: bool,
    /// Set to `false` by the capture thread when it exits (cleanly or on
    /// error), so callers can tell a live stream from one whose thread died
    /// because the device was unplugged. `None` while not streaming.
    running: Option<Arc<AtomicBool>>,
}

/// Capture geometry handed to the capture thread.
struct CaptureSpec {
    path: PathBuf,
    width: u32,
    height: u32,
    fps: u32,
    fourcc: [u8; 4],
}

impl V4lSource {
    pub fn new(
        path: impl AsRef<Path>,
        width: u32,
        height: u32,
        fps: u32,
        fourcc: [u8; 4],
    ) -> HwResult<Self> {
        let path = path.as_ref().to_path_buf();
        let probe = discover::probe_device(&path)?;
        Ok(Self {
            path,
            width,
            height,
            fps,
            fourcc,
            identity: probe.identity,
            control: None,
            frames: None,
            started: false,
            running: None,
        })
    }

    /// Expected frame size in bytes for the configured format.
    pub fn frame_size(&self) -> Option<usize> {
        let fmt = PixelFormat::from_fourcc(&self.fourcc);
        fmt.bytes_per_pixel()
            .map(|bpp| (self.width * self.height) as usize * bpp)
    }

    fn spawn_capture_thread(
        spec: CaptureSpec,
        frames: SyncSender<Frame>,
        shutdown: Receiver<()>,
        running: Arc<AtomicBool>,
    ) -> HwResult<()> {
        std::thread::Builder::new()
            .name("hiro-capture".into())
            .spawn(move || {
                let run = || -> HwResult<()> {
                    let dev = Device::with_path(&spec.path).map_err(|e| {
                        HwError::Camera(format!("cannot open {}: {e}", spec.path.display()))
                    })?;

                    let requested = Format::new(spec.width, spec.height, FourCC::new(&spec.fourcc));
                    let negotiated = match dev.set_format(&requested) {
                        Ok(f) => f,
                        Err(_) => {
                            // The node may not support the configured FourCC
                            // (e.g. an IR node exposing only GREY). Fall back
                            // to a supported 8-bit luma format, then anything.
                            let formats = dev.enum_formats().unwrap_or_default();
                            let pick = formats
                                .iter()
                                .find(|d| d.fourcc.str().is_ok_and(|s| s == "GREY" || s == "GRAY"))
                                .or_else(|| formats.first());
                            match pick {
                                Some(d) => dev
                                    .set_format(&Format::new(spec.width, spec.height, d.fourcc))
                                    .map_err(|e| {
                                        HwError::UnsupportedFormat(format!(
                                            "{}: no compatible capture format: {e}",
                                            spec.path.display()
                                        ))
                                    })?,
                                None => {
                                    return Err(HwError::UnsupportedFormat(format!(
                                        "{} lists no capture formats",
                                        spec.path.display()
                                    )));
                                }
                            }
                        }
                    };
                    let neg_fourcc: [u8; 4] = u32::from(negotiated.fourcc).to_le_bytes();
                    let (fwidth, fheight) = (negotiated.width.max(1), negotiated.height.max(1));
                    if neg_fourcc != spec.fourcc || fwidth != spec.width || fheight != spec.height {
                        log::warn!(
                            "camera negotiated {} {}x{} (configured: {} {}x{}) on {}",
                            String::from_utf8_lossy(&neg_fourcc),
                            fwidth,
                            fheight,
                            String::from_utf8_lossy(&spec.fourcc),
                            spec.width,
                            spec.height,
                            spec.path.display()
                        );
                    }

                    if spec.fps > 0 {
                        let _ = dev.set_params(&Parameters::with_fps(spec.fps));
                    }

                    let mut stream = MmapStream::with_buffers(&dev, Type::VideoCapture, 4)
                        .map_err(|e| {
                            HwError::Camera(format!(
                                "cannot set up mmap stream on {}: {e}",
                                spec.path.display()
                            ))
                        })?;
                    stream.set_timeout(Duration::from_millis(500));

                    let t0 = std::time::Instant::now();
                    loop {
                        if shutdown.try_recv().is_ok() {
                            break;
                        }
                        match stream.next() {
                            Ok((buf, meta)) => {
                                let frame = Frame {
                                    width: fwidth,
                                    height: fheight,
                                    format: PixelFormat::from_fourcc(&neg_fourcc),
                                    data: buf.to_vec(),
                                    seq: meta.sequence,
                                    timestamp_ms: t0.elapsed().as_millis() as u64,
                                };
                                if frames.send(frame).is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                // The v4l crate's Stream::next() re-queues
                                // the previously dequeued buffer *before*
                                // polling; after a poll timeout that buffer
                                // is still queued, so the next call would
                                // re-queue it again and the driver returns
                                // EINVAL. Stop the stream so the next call
                                // re-queues every buffer cleanly.
                                log::debug!(
                                    "capture: frame read timed out on {}; resetting stream",
                                    spec.path.display()
                                );
                                let _ = StreamTrait::stop(&mut stream);
                            }
                            Err(e) => {
                                return Err(HwError::Camera(format!(
                                    "capture failed on {}: {e}",
                                    spec.path.display()
                                )));
                            }
                        }
                    }
                    let _ = StreamTrait::stop(&mut stream);
                    Ok(())
                };
                if let Err(e) = run() {
                    log::warn!("capture thread stopped: {e}");
                }
                // The thread is exiting, for whatever reason: a live stream
                // has become a dead one. Callers poll this flag (is_alive)
                // so the session can rebuild the source instead of serving a
                // dead channel forever.
                running.store(false, Ordering::SeqCst);
            })
            .map_err(|e| HwError::Camera(format!("cannot spawn capture thread: {e}")))?;
        Ok(())
    }
}

impl VideoSource for V4lSource {
    fn start(&mut self) -> HwResult<()> {
        if self.started {
            return Ok(());
        }
        // Fail fast if the node is gone or unopenable (e.g. the camera was
        // unplugged since the source was built). Without this check the
        // capture thread would spawn, fail to open the device, and exit,
        // and the caller would only discover the failure on the *next*
        // frame read as "capture thread exited".
        discover::probe_device(&self.path).inspect_err(|_| {
            // Mark the source dead so the session re-discovers (and
            // re-picks) the camera on its next acquire() instead of
            // retrying this stale path — the camera may have returned at a
            // different /dev/videoN node.
            self.running = Some(Arc::new(AtomicBool::new(false)));
        })?;
        let (control_tx, control_rx) = sync_channel::<()>(1);
        let (frame_tx, frame_rx) = sync_channel::<Frame>(4);
        let running = Arc::new(AtomicBool::new(true));
        let running_in_thread = running.clone();
        Self::spawn_capture_thread(
            CaptureSpec {
                path: self.path.clone(),
                width: self.width,
                height: self.height,
                fps: self.fps,
                fourcc: self.fourcc,
            },
            frame_tx,
            control_rx,
            running_in_thread,
        )?;
        self.control = Some(control_tx);
        self.frames = Some(frame_rx);
        self.running = Some(running);
        self.started = true;
        Ok(())
    }

    fn next_frame(&mut self, timeout: Duration) -> HwResult<Option<Frame>> {
        let rx = self
            .frames
            .as_ref()
            .ok_or_else(|| HwError::Invalid("stream not started".into()))?;
        match rx.recv_timeout(timeout) {
            Ok(frame) => Ok(Some(frame)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.started = false;
                Err(HwError::Camera("capture thread exited".into()))
            }
        }
    }

    fn stop(&mut self) {
        if let Some(ctl) = self.control.take() {
            let _ = ctl.send(());
        }
        self.frames = None;
        self.started = false;
        self.running = None;
    }

    fn drain(&mut self) {
        if let Some(rx) = &self.frames {
            // The capture thread is bounded by the channel: it fills up to
            // `capacity` frames while the stream sat warm, then blocks.
            // Drop all of them so the next request reads only frames
            // captured after it started.
            while rx.try_recv().is_ok() {}
        }
    }

    fn is_alive(&self) -> bool {
        // No running flag: not started (or stopped cleanly) — a healthy
        // state that `start()` can resume. A flag the capture thread has
        // cleared (device unplugged, I/O error killed the thread) means the
        // source is dead and the session must re-discover and rebuild it.
        self.running
            .as_ref()
            .is_none_or(|r| r.load(Ordering::SeqCst))
    }

    fn identity(&self) -> CameraIdentity {
        self.identity.clone()
    }

    fn describe(&self) -> String {
        format!(
            "{} {}x{}@{} {}",
            self.path.display(),
            self.width,
            self.height,
            self.fps,
            String::from_utf8_lossy(&self.fourcc)
        )
    }
}
