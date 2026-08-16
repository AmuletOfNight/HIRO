//! V4L2 capture behind a [`VideoSource`] abstraction.

use std::path::{Path, PathBuf};
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
        })
    }

    /// Expected frame size in bytes for the configured format.
    pub fn frame_size(&self) -> Option<usize> {
        let fmt = PixelFormat::from_fourcc(&self.fourcc);
        fmt.bytes_per_pixel()
            .map(|bpp| (self.width * self.height) as usize * bpp)
    }

    fn spawn_capture_thread(
        path: PathBuf,
        width: u32,
        height: u32,
        fps: u32,
        fourcc: [u8; 4],
        frames: SyncSender<Frame>,
        shutdown: Receiver<()>,
    ) -> HwResult<()> {
        std::thread::Builder::new()
            .name("hiro-capture".into())
            .spawn(move || {
                let run = || -> HwResult<()> {
                    let dev = Device::with_path(&path).map_err(|e| {
                        HwError::Camera(format!("cannot open {}: {e}", path.display()))
                    })?;

                    let requested = Format::new(width, height, FourCC::new(&fourcc));
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
                                    .set_format(&Format::new(width, height, d.fourcc))
                                    .map_err(|e| {
                                        HwError::UnsupportedFormat(format!(
                                            "{}: no compatible capture format: {e}",
                                            path.display()
                                        ))
                                    })?,
                                None => {
                                    return Err(HwError::UnsupportedFormat(format!(
                                        "{} lists no capture formats",
                                        path.display()
                                    )));
                                }
                            }
                        }
                    };
                    let neg_fourcc: [u8; 4] = u32::from(negotiated.fourcc).to_le_bytes();
                    let (fwidth, fheight) = (negotiated.width.max(1), negotiated.height.max(1));
                    if neg_fourcc != fourcc || fwidth != width || fheight != height {
                        log::warn!(
                            "camera negotiated {} {}x{} (configured: {} {}x{}) on {}",
                            String::from_utf8_lossy(&neg_fourcc),
                            fwidth,
                            fheight,
                            String::from_utf8_lossy(&fourcc),
                            width,
                            height,
                            path.display()
                        );
                    }

                    if fps > 0 {
                        let _ = dev.set_params(&Parameters::with_fps(fps));
                    }

                    let mut stream = MmapStream::with_buffers(&dev, Type::VideoCapture, 4)
                        .map_err(|e| {
                            HwError::Camera(format!(
                                "cannot set up mmap stream on {}: {e}",
                                path.display()
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
                                    path.display()
                                );
                                let _ = StreamTrait::stop(&mut stream);
                            }
                            Err(e) => {
                                return Err(HwError::Camera(format!(
                                    "capture failed on {}: {e}",
                                    path.display()
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
        let (control_tx, control_rx) = sync_channel::<()>(1);
        let (frame_tx, frame_rx) = sync_channel::<Frame>(4);
        Self::spawn_capture_thread(
            self.path.clone(),
            self.width,
            self.height,
            self.fps,
            self.fourcc,
            frame_tx,
            control_rx,
        )?;
        self.control = Some(control_tx);
        self.frames = Some(frame_rx);
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
