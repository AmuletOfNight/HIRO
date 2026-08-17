//! Hardware smoke test: real V4L2 capture from an IR node.
//!
//! Runs only with `cargo test -- --ignored` since it requires a physical
//! camera. Validates discovery, format negotiation, and the capture
//! thread on the actual Windows Hello / IR hardware.

use std::time::Duration;

use hiro_hw::capture::{V4lSource, VideoSource};

#[test]
#[ignore = "requires a V4L2 capture device"]
fn capture_frames_from_ir_node() {
    let probes = hiro_hw::discover::probe_devices();
    let probe =
        hiro_hw::discover::pick_capture_device(&probes, None).expect("no capture device found");

    // Prefer an 8-bit luma format when the node offers one.
    let fourcc = if probe.formats.iter().any(|f| f == "GREY" || f == "GRAY") {
        *b"GREY"
    } else {
        *b"YUYV"
    };
    println!(
        "using {} ({}x480@30 {})",
        probe.path,
        640,
        String::from_utf8_lossy(&fourcc)
    );

    let mut src = V4lSource::new(&probe.path, 640, 480, 30, fourcc).unwrap();
    src.start().unwrap();

    let mut means = Vec::new();
    for _ in 0..30 {
        let frame = src
            .next_frame(Duration::from_secs(3))
            .unwrap()
            .expect("timed out");
        let gray = frame.to_gray().expect("format has no luma");
        let mean = gray.iter().map(|&v| f64::from(v)).sum::<f64>() / gray.len() as f64;
        means.push(mean);
    }
    src.stop();

    let overall = means.iter().sum::<f64>() / means.len() as f64;
    let max = means.iter().cloned().fold(f64::MIN, f64::max);
    let min = means.iter().cloned().fold(f64::MAX, f64::min);
    println!(
        "luma mean={overall:.1} min={min:.1} max={max:.1} over {} frames",
        means.len()
    );

    assert!(
        overall > 1.0,
        "camera appears to deliver a dead/black stream"
    );
    assert!(
        max - min > 0.5,
        "no temporal variation; check the IR emitter"
    );
}

#[test]
#[ignore = "requires a V4L2 capture device"]
fn discover_and_classify() {
    let probes = hiro_hw::discover::probe_devices();
    let summary = hiro_hw::discover::summarize(&probes);
    println!("{summary}");
    assert!(!probes.is_empty(), "no /dev/video* devices at all");
}

/// Capture frames from the IR node, run the ONNX detector on each, and
/// save the frames as PGMs for inspection. Run WITH the models dir set:
///
///   HIRO_MODELS_DIR=/usr/share/hiro/models cargo test -p hiro-hw --test hardware detect_frames -- --ignored --nocapture
///
/// Face the camera for the whole run.
#[test]
#[ignore = "requires a V4L2 capture device"]
fn detect_frames() {
    use hiro_face::onnx::OnnxPipeline;

    let out_dir = std::path::PathBuf::from("/tmp/hiro-frames");
    std::fs::create_dir_all(&out_dir).unwrap();

    let probes = hiro_hw::discover::probe_devices();
    let probe = hiro_hw::discover::pick_capture_device(&probes, None).unwrap();
    let fourcc = if probe.formats.iter().any(|f| f == "GREY" || f == "GRAY") {
        *b"GREY"
    } else {
        *b"YUYV"
    };
    println!("camera: {} ({}x480)", probe.path, 640);

    let mut src = hiro_hw::capture::V4lSource::new(&probe.path, 640, 480, 30, fourcc).unwrap();
    src.start().unwrap();

    let pipeline = std::env::var("HIRO_MODELS_DIR").ok().map(|dir| {
        let cfg = hiro_core::config::RecognitionConfig {
            model_dir: std::path::PathBuf::from(dir),
            ..hiro_core::config::RecognitionConfig::default()
        };
        OnnxPipeline::new(&cfg).expect("load ONNX pipeline")
    });

    let mut dets_total = 0usize;
    let mut best: Option<f32> = None;
    for i in 0..30u32 {
        let frame = src
            .next_frame(std::time::Duration::from_secs(3))
            .unwrap()
            .expect("timeout");
        let gray = frame.to_gray().expect("luma");
        let mean = gray.iter().map(|&v| f64::from(v)).sum::<f64>() / gray.len() as f64;

        if let Some(p) = &pipeline {
            let dets = p
                .detect_boxes(&gray, frame.width, frame.height)
                .expect("detect");
            let top = dets.iter().map(|d| d.score).fold(f32::MIN, f32::max);
            let stats = p
                .raw_score_stats(&gray, frame.width, frame.height)
                .expect("stats");
            let stats_str = stats
                .iter()
                .map(|s| format!("{s:.3}"))
                .collect::<Vec<_>>()
                .join(",");
            if let Some(b) = best {
                if top > b {
                    best = Some(top);
                }
            } else {
                best = Some(top);
            }
            dets_total += dets.len();
            println!(
                "frame {i:02}: mean={mean:6.1} dets={:<3} top_score={top:.3} max_sigmoid=[{stats_str}]",
                dets.len()
            );
        } else {
            println!("frame {i:02}: mean={mean:6.1} (no models; set HIRO_MODELS_DIR to detect)");
        }

        let path = out_dir.join(format!("frame_{i:02}.pgm"));
        let mut data = format!("P5\n{} {}\n255\n", frame.width, frame.height).into_bytes();
        data.extend_from_slice(&gray);
        std::fs::write(&path, data).unwrap();
    }
    src.stop();
    println!("total detections across 30 frames: {dets_total}");
    println!("best score: {:?}", best);
    println!("frames saved to {}", out_dir.display());
}
