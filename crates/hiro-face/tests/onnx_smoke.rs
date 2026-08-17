//! ONNX pipeline smoke test against real model files.
//!
//! Requires `HIRO_MODELS_DIR` to point at a directory containing the
//! manifest's model files (see scripts/fetch-models.sh). Runs only with
//! `cargo test --features onnx -- --ignored onnx_smoke`.
#![cfg(feature = "onnx")]

use hiro_core::config::RecognitionConfig;

#[test]
#[ignore = "requires real model files and the onnx feature"]
fn dump_io_names() {
    let model_dir = std::env::var("HIRO_MODELS_DIR").expect("set HIRO_MODELS_DIR");
    let det_path = std::path::Path::new(&model_dir).join("scrfd_10g_bnkps.onnx");
    let mut session = ort::session::Session::builder()
        .unwrap()
        .with_intra_threads(1)
        .unwrap()
        .commit_from_file(&det_path)
        .unwrap();
    for (i, io) in session.inputs().iter().enumerate() {
        println!("input {i}: name={}", io.name());
    }
    for (i, io) in session.outputs().iter().enumerate() {
        println!("output {i}: name={}", io.name());
    }
    // Print runtime shapes by running once on zeros.
    let size = 640usize;
    let data = vec![0.0f32; 3 * size * size];
    let tensor =
        ort::value::Tensor::from_array((vec![1i64, 3, size as i64, size as i64], data)).unwrap();
    let out = session.run(ort::inputs!["input.1" => tensor]).unwrap();
    for (i, (name, value)) in out.iter().enumerate() {
        if let Ok((shape, _)) = value.try_extract_tensor::<f32>() {
            let dims: Vec<i64> = shape.iter().copied().collect();
            let total: usize = dims.iter().map(|&d| d.max(0) as usize).product();
            let classified = hiro_face::onnx::classify_branch_pub(total);
            println!("runtime output {i}: name={name} shape={dims:?} total={total} classified={classified:?}");
        } else {
            println!("runtime output {i}: name={name} <non-f32>");
        }
    }
}

#[test]
#[ignore = "requires real model files and the onnx feature"]
fn onnx_smoke() {
    let model_dir = std::env::var("HIRO_MODELS_DIR").expect("set HIRO_MODELS_DIR");
    let mut cfg = RecognitionConfig {
        model_dir: std::path::PathBuf::from(&model_dir),
        ..RecognitionConfig::default()
    };
    cfg.match_threshold = 0.60;

    let pipeline = hiro_face::create(&cfg).expect("ONNX pipeline should load");
    assert!(pipeline.loaded());
    assert_eq!(pipeline.name(), "onnx");

    // Synthetic noise frame: detector should find nothing (no crash).
    let w = 320u32;
    let h = 240u32;
    let mut luma = vec![0u8; (w * h) as usize];
    for (i, v) in luma.iter_mut().enumerate() {
        *v = ((i as f32 * 0.001).sin().abs() * 255.0) as u8;
    }
    let result = pipeline.process(&luma, w, h).expect("pipeline runs");
    println!("noise frame -> {:?}", result.map(|h| h.det_score));

    // Optional real-frame diagnostic: HIRO_PGM points at a captured PGM.
    if let Ok(pgm) = std::env::var("HIRO_PGM") {
        let data = std::fs::read(&pgm).expect("read PGM");
        // P5 header: "P5\n<w> <h>\n<max>\n" followed by binary data.
        let mut pos = 0usize;
        let next_token = |pos: &mut usize| -> String {
            while *pos < data.len() && data[*pos].is_ascii_whitespace() {
                *pos += 1;
            }
            let start = *pos;
            while *pos < data.len() && !data[*pos].is_ascii_whitespace() {
                *pos += 1;
            }
            String::from_utf8_lossy(&data[start..*pos]).into_owned()
        };
        let magic = next_token(&mut pos);
        assert_eq!(magic, "P5", "expected P5 magic, got {magic:?}");
        let pw: u32 = next_token(&mut pos).parse().expect("width int");
        let ph: u32 = next_token(&mut pos).parse().expect("height int");
        let _max: u32 = next_token(&mut pos).parse().expect("maxval int");
        while pos < data.len() && data[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let luma = data[pos..].to_vec();
        assert_eq!(luma.len(), (pw * ph) as usize, "PGM body size");
        println!("PGM {pw}x{ph} bytes={}", luma.len());
        let mean = luma.iter().map(|&v| f64::from(v)).sum::<f64>() / luma.len() as f64;
        println!("PGM mean luma = {mean:.1}");
        let hit = pipeline
            .process(&luma, pw, ph)
            .expect("pipeline on real frame");
        match &hit {
            Some(h) => println!(
                "REAL FRAME DETECTED score={} bbox={:?}",
                h.det_score, h.bbox
            ),
            None => println!("REAL FRAME: no face"),
        }
        // Per-output diagnostics via a second pipeline instance.
        if let Ok(raw) = hiro_face::onnx::OnnxPipeline::new(&cfg) {
            for mode in 0..4u8 {
                let stats = raw
                    .raw_score_stats_norm(&luma, pw, ph, mode)
                    .expect("stats");
                let scores: Vec<String> = stats.iter().map(|s| format!("{s:.3}")).collect();
                println!("NORM {mode}: max-per-map=[{}]", scores.join(", "));
            }
            let dets = raw.detect_boxes(&luma, pw, ph).expect("detect");
            println!("detections:");
            for d in dets.iter().take(8) {
                println!("  score={:.3} bbox={:?}", d.score, d.bbox);
            }
        }
    }
}
