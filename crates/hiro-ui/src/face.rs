//! Cairo-drawn status glyph for the status card.
//!
//! Renders the full HIRO logo (`Logo/HIRO.svg`'s raster export, shipped as
//! `assets/hiro-logo.png`) as the status glyph, with only the logo's own
//! strokes drawn — the background stays transparent. The logo's stroke is a
//! neutral slate, so it is pre-tinted with the status accent exactly like the
//! old ring/eyes/mouth drawing (amber while scanning, green on success, red
//! on failure, ...). While scanning, corner brackets plus a sweeping
//! highlight line animate across it. `sweep` sweeps 0.0..=1.0 once per
//! animation period; `breathe` scales the whole glyph slightly so it feels
//! alive.
//!
//! If the embedded logo cannot be decoded (gdk-pixbuf unavailable), the
//! drawing falls back to the hand-drawn ring/eyes/mouth glyph.

use std::cell::RefCell;
use std::f64::consts::PI;

use gtk::cairo::{Context, LineCap};
use gtk::gdk::prelude::GdkContextExt;
use gtk::gdk_pixbuf::{InterpType, Pixbuf};

/// The full HIRO logo, byte-for-byte as shipped in `Logo/HIRO.png`. RGBA,
/// 1045×1185; the logo's stroke is a neutral slate so it takes whatever
/// accent colour the current status needs.
const LOGO_PNG: &[u8] = include_bytes!("../assets/hiro-logo.png");

/// Display height (px) of the pre-scaled copy used at draw time. The logo is
/// shown at ~60 px in the 64-grid, so a 240 px copy keeps it crisp up to 4×
/// HiDPI while keeping the per-frame draw cost low.
const LOGO_TARGET_H: i32 = 240;

thread_local! {
    /// Lazily decoded and pre-scaled base logo. The GTK draw path only ever
    /// runs on the main thread, so a `thread_local` avoids any Send/Sync
    /// questions around `Pixbuf` and means a decode failure is a graceful
    /// one-time miss.
    static LOGO: RefCell<Option<Pixbuf>> = const { RefCell::new(None) };
    /// Per-state pre-tinted copies (accent applied at load time), so the
    /// draw path never relies on Cairo operator tricks.
    static TINTED: RefCell<Vec<(FaceState, Pixbuf)>> = const { RefCell::new(Vec::new()) };
}

/// Facial expression states, one per UI status colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceState {
    Idle,
    Scanning,
    Enrolling,
    Success,
    Warn,
    Fail,
    Approval,
}

impl FaceState {
    /// Accent colour as (r, g, b) in 0..=1, matching the extension's palette.
    fn accent(self) -> (f64, f64, f64) {
        match self {
            FaceState::Idle => (0.788, 0.820, 0.851),      // #c9d1d9
            FaceState::Scanning => (1.0, 0.820, 0.400),    // #ffd166
            FaceState::Enrolling => (0.310, 0.765, 0.969), // #4fc3f7
            FaceState::Success => (0.400, 0.733, 0.416),   // #66bb6a
            FaceState::Fail => (0.898, 0.451, 0.451),      // #e57373
            FaceState::Warn => (1.0, 0.702, 0.302),        // #ffb74d
            FaceState::Approval => (0.729, 0.490, 0.784),  // #ba68c8
        }
    }
}

/// Geometry of the scan bracket frame and the sweeping highlight, in the
/// Cairo context's user space (already scaled from the 64×64 design grid).
struct ScanFrame {
    /// Bracket frame (L-corners) bounds.
    fx: f64,
    fy: f64,
    fw: f64,
    fh: f64,
    /// Sweeping highlight band: x origin, width, and vertical sweep range.
    sweep_x: f64,
    sweep_w: f64,
    sweep_a: f64,
    sweep_b: f64,
}

/// Paint the face glyph centred in a surface of the given size.
///
/// Cairo operations return `Result`s that are irrelevant here (a failure to
/// paint a decorative glyph is not actionable), so the errors are ignored.
#[allow(unused_must_use)]
pub fn draw_face(cr: &Context, w: f64, h: f64, state: FaceState, sweep: f64, breathe: f64) {
    let scale = (w / 64.0).min(h / 64.0).max(0.001);
    let (r, g, b) = state.accent();
    let scanning = matches!(state, FaceState::Scanning | FaceState::Enrolling);
    let cx = 32.0 * scale;
    let cy = 32.0 * scale;

    cr.save();
    if (breathe - 1.0).abs() > 1e-9 {
        cr.translate(cx, cy);
        cr.scale(breathe, breathe);
        cr.translate(-cx, -cy);
    }

    let set = |alpha: f64| cr.set_source_rgba(r, g, b, alpha);

    let frame = match logo_pixbuf(state) {
        Some(pb) => {
            // The logo is portrait (smiley over the HIRO wordmark), so fit it
            // to the 60-tall scan zone (2..62 of the 64-grid), centred. Only
            // the logo's own strokes are drawn — the background stays
            // transparent so the card colour shows through.
            let aspect = pb.width() as f64 / pb.height() as f64;
            let th = 60.0 * scale;
            let tw = th * aspect;
            let dx = cx - tw / 2.0;
            let dy = cy - th / 2.0;

            cr.save();
            cr.translate(dx, dy);
            cr.scale(tw / pb.width() as f64, th / pb.height() as f64);
            cr.set_source_pixbuf(&pb, 0.0, 0.0);
            cr.paint();
            cr.restore();

            ScanFrame {
                fx: dx - 1.5 * scale,
                fy: dy - 1.5 * scale,
                fw: tw + 3.0 * scale,
                fh: th + 3.0 * scale,
                sweep_x: dx + 2.0 * scale,
                sweep_w: tw - 4.0 * scale,
                sweep_a: dy + 2.0 * scale,
                sweep_b: dy + th - 2.0 * scale,
            }
        }
        None => {
            // Fallback: the legacy hand-drawn smiley glyph.
            draw_legacy_face(cr, scale, cx, cy, state, &set);
            ScanFrame {
                fx: 6.0 * scale,
                fy: 6.0 * scale,
                fw: 52.0 * scale,
                fh: 52.0 * scale,
                sweep_x: 13.0 * scale,
                sweep_w: 38.0 * scale,
                sweep_a: 23.0 * scale,
                sweep_b: 41.0 * scale,
            }
        }
    };

    // Scan brackets and the sweeping highlight while scanning.
    if scanning {
        let arm = 8.0 * scale;
        cr.set_line_width(2.0 * scale);
        set(1.0);
        cr.new_sub_path();
        cr.move_to(frame.fx, frame.fy + arm);
        cr.line_to(frame.fx, frame.fy);
        cr.line_to(frame.fx + arm, frame.fy);
        cr.move_to(frame.fx + frame.fw - arm, frame.fy);
        cr.line_to(frame.fx + frame.fw, frame.fy);
        cr.line_to(frame.fx + frame.fw, frame.fy + arm);
        cr.move_to(frame.fx, frame.fy + frame.fh - arm);
        cr.line_to(frame.fx, frame.fy + frame.fh);
        cr.line_to(frame.fx + arm, frame.fy + frame.fh);
        cr.move_to(frame.fx + frame.fw - arm, frame.fy + frame.fh);
        cr.line_to(frame.fx + frame.fw, frame.fy + frame.fh);
        cr.line_to(frame.fx + frame.fw, frame.fy + frame.fh - arm);
        cr.stroke();

        let sweep_y = frame.sweep_a + sweep * (frame.sweep_b - frame.sweep_a);
        set(0.16);
        round_rect(
            cr,
            frame.sweep_x,
            sweep_y - 5.0 * scale,
            frame.sweep_w,
            10.0 * scale,
            5.0 * scale,
        );
        cr.fill();
        set(1.0);
        round_rect(
            cr,
            frame.sweep_x,
            sweep_y - 1.0 * scale,
            frame.sweep_w,
            2.5 * scale,
            1.5 * scale,
        );
        cr.fill();
    }

    cr.restore();
}

/// The pre-logo hand-drawn glyph, used only if the embedded logo cannot be
/// decoded. Kept deliberately simple so a gdk-pixbuf failure degrades
/// gracefully instead of leaving the card's face blank.
#[allow(unused_must_use)]
fn draw_legacy_face(
    cr: &Context,
    scale: f64,
    cx: f64,
    cy: f64,
    state: FaceState,
    set: &impl Fn(f64),
) {
    // Ring and face plate.
    set(0.92);
    cr.set_line_width(1.6 * scale);
    cr.set_line_cap(LineCap::Round);
    cr.arc(cx, cy, 25.0 * scale, 0.0, 2.0 * PI);
    cr.stroke();

    set(0.08);
    cr.arc(cx, cy, 21.5 * scale, 0.0, 2.0 * PI);
    cr.fill();

    // Eyes.
    set(1.0);
    round_rect(
        cr,
        20.5 * scale,
        23.0 * scale,
        7.0 * scale,
        9.0 * scale,
        3.0 * scale,
    );
    cr.fill();
    round_rect(
        cr,
        36.5 * scale,
        23.0 * scale,
        7.0 * scale,
        9.0 * scale,
        3.0 * scale,
    );
    cr.fill();

    // Mouth: smile, or frown for failure/warning states.
    cr.set_line_width(2.0 * scale);
    if matches!(state, FaceState::Fail | FaceState::Warn) {
        cr.arc(cx, 41.0 * scale, 8.0 * scale, PI * 1.15, PI * 1.85);
    } else {
        cr.arc(cx, 37.5 * scale, 9.0 * scale, PI * 0.15, PI * 0.85);
    }
    cr.stroke();
}

/// The status-tinted logo for `state`, cached per state. `None` on any
/// failure (missing gdk-pixbuf loader, corrupt asset, ...); callers fall back
/// to the legacy glyph.
fn logo_pixbuf(state: FaceState) -> Option<Pixbuf> {
    TINTED.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((_, pb)) = cache.iter().find(|(s, _)| *s == state) {
            return Some(pb.clone());
        }
        let base = load_base_logo()?;
        let pb = tint(&base, state.accent())?;
        cache.push((state, pb.clone()));
        Some(pb)
    })
}

/// Lazily decode `LOGO_PNG` and pre-scale it to `LOGO_TARGET_H` px tall
/// (preserving aspect) so per-frame drawing stays cheap.
fn load_base_logo() -> Option<Pixbuf> {
    LOGO.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            let full = Pixbuf::from_read(LOGO_PNG).ok()?;
            let w = full.width();
            let h = full.height();
            if h <= LOGO_TARGET_H {
                slot.replace(full);
            } else {
                let target_w = ((w as f64 / h as f64) * LOGO_TARGET_H as f64).round() as i32;
                slot.replace(full.scale_simple(
                    target_w.max(1),
                    LOGO_TARGET_H,
                    InterpType::Bilinear,
                )?);
            }
        }
        slot.clone()
    })
}

/// Replace the logo's RGB channels with the accent colour, keeping its alpha
/// (the logo stroke is a neutral slate, so this just recolours it).
fn tint(base: &Pixbuf, (r, g, b): (f64, f64, f64)) -> Option<Pixbuf> {
    let out = base.copy()?;
    let nch = out.n_channels();
    let rowstride = out.rowstride();
    let cr = (r * 255.0).round() as u8;
    let cg = (g * 255.0).round() as u8;
    let cb = (b * 255.0).round() as u8;
    let px = unsafe { out.pixels() };
    for row in 0..out.height() {
        for col in 0..out.width() {
            let i = (row * rowstride + col * nch) as usize;
            px[i] = cr;
            px[i + 1] = cg;
            px[i + 2] = cb;
        }
    }
    Some(out)
}

/// Rounded-rectangle helper (ports the extension's `_roundRect`).
#[allow(unused_must_use)]
fn round_rect(cr: &Context, x: f64, y: f64, w: f64, h: f64, rad: f64) {
    let rad = rad.min(w / 2.0).min(h / 2.0);
    cr.new_sub_path();
    cr.arc(x + rad, y + rad, rad, PI, 1.5 * PI);
    cr.arc(x + w - rad, y + rad, rad, 1.5 * PI, 0.0);
    cr.arc(x + w - rad, y + h - rad, rad, 0.0, 0.5 * PI);
    cr.arc(x + rad, y + h - rad, rad, 0.5 * PI, PI);
    cr.close_path();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accents_are_distinct() {
        // Compare rounded 8-bit values (f64 is neither Eq nor Hash).
        fn key(c: (f64, f64, f64)) -> (i32, i32, i32) {
            (
                (c.0 * 255.0).round() as i32,
                (c.1 * 255.0).round() as i32,
                (c.2 * 255.0).round() as i32,
            )
        }
        let mut seen = std::collections::HashSet::new();
        for s in [
            FaceState::Idle,
            FaceState::Scanning,
            FaceState::Enrolling,
            FaceState::Success,
            FaceState::Warn,
            FaceState::Fail,
            FaceState::Approval,
        ] {
            assert!(seen.insert(key(s.accent())), "duplicate accent for {s:?}");
        }
    }

    #[test]
    fn embedded_logo_is_png() {
        // The asset must stay a valid PNG (magic header + IEND trailer).
        assert_eq!(&LOGO_PNG[..8], b"\x89PNG\r\n\x1a\n");
        assert!(LOGO_PNG.len() > 16);
        assert_eq!(&LOGO_PNG[LOGO_PNG.len() - 8..], b"IEND\xaeB`\x82");
    }

    #[test]
    fn tint_preserves_alpha_and_sets_accent() {
        // Load the base logo, tint it Scanning-amber, and confirm the RGB is
        // the accent while transparency (alpha) is untouched.
        let base = load_base_logo().expect("logo must load");
        let amber = FaceState::Scanning.accent();
        let tinted = tint(&base, amber).expect("tint must succeed");
        assert_eq!(base.width(), tinted.width());
        assert_eq!(base.height(), tinted.height());
        assert_eq!(tinted.n_channels(), base.n_channels());
        let nch = base.n_channels();
        let rowstride = tinted.rowstride();
        let b = unsafe { base.pixels() };
        let t = unsafe { tinted.pixels() };
        let mut colored = 0;
        let mut transparent_kept = 0;
        for row in (0..tinted.height()).step_by(4) {
            for col in (0..tinted.width()).step_by(4) {
                let i = (row * rowstride + col * nch) as usize;
                if b[i + 3] > 0 {
                    assert_eq!(t[i], (amber.0 * 255.0).round() as u8, "R at ({col},{row})");
                    assert_eq!(
                        t[i + 1],
                        (amber.1 * 255.0).round() as u8,
                        "G at ({col},{row})"
                    );
                    assert_eq!(
                        t[i + 2],
                        (amber.2 * 255.0).round() as u8,
                        "B at ({col},{row})"
                    );
                    assert_eq!(t[i + 3], b[i + 3], "alpha changed at ({col},{row})");
                    colored += 1;
                } else {
                    transparent_kept += 1;
                }
            }
        }
        assert!(colored > 0, "no opaque pixels to tint");
        assert!(
            transparent_kept > 0,
            "no transparent pixels — logo is not see-through"
        );
    }

    #[test]
    fn draws_without_panicking() {
        // Paint onto an in-memory surface the way the widget would. The
        // embedded logo is decoded lazily; if gdk-pixbuf is unavailable in
        // the test environment the legacy glyph is drawn instead — the point
        // here is that neither path panics.
        let surface = gtk::cairo::ImageSurface::create(gtk::cairo::Format::ARgb32, 64, 64).unwrap();
        let cr = Context::new(&surface).unwrap();
        for s in [
            FaceState::Idle,
            FaceState::Scanning,
            FaceState::Enrolling,
            FaceState::Success,
            FaceState::Warn,
            FaceState::Fail,
            FaceState::Approval,
        ] {
            draw_face(&cr, 64.0, 64.0, s, 0.5, 1.0);
            draw_face(&cr, 64.0, 64.0, s, 0.0, 1.05);
            draw_face(&cr, 64.0, 64.0, s, 1.0, 0.95);
        }
    }
}
