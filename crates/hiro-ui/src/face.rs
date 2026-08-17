//! Cairo-drawn "face" glyph for the status card.
//!
//! A faithful port of the GNOME Shell extension's `_drawFace`: ring, eyes,
//! mouth, and (while scanning) corner brackets plus a sweeping highlight
//! line. `sweep` sweeps 0.0..=1.0 once per animation period; `breathe`
//! scales the whole glyph slightly so it feels alive.

use std::f64::consts::PI;

use gtk::cairo::{Context, LineCap};

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

    // Outer glow, ring, and face plate.
    set(0.10);
    cr.arc(cx, cy, 26.0 * scale, 0.0, 2.0 * PI);
    cr.fill();

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

    // Scan brackets and the sweeping highlight while scanning.
    if scanning {
        cr.set_line_width(2.0 * scale);
        set(1.0);
        cr.new_sub_path();
        cr.move_to(6.0 * scale, 14.0 * scale);
        cr.line_to(6.0 * scale, 6.0 * scale);
        cr.line_to(14.0 * scale, 6.0 * scale);
        cr.move_to(50.0 * scale, 6.0 * scale);
        cr.line_to(58.0 * scale, 6.0 * scale);
        cr.line_to(58.0 * scale, 14.0 * scale);
        cr.move_to(6.0 * scale, 50.0 * scale);
        cr.line_to(6.0 * scale, 58.0 * scale);
        cr.line_to(14.0 * scale, 58.0 * scale);
        cr.move_to(50.0 * scale, 58.0 * scale);
        cr.line_to(58.0 * scale, 58.0 * scale);
        cr.line_to(58.0 * scale, 50.0 * scale);
        cr.stroke();

        let sweep_y = (23.0 + sweep * 18.0) * scale;
        set(0.16);
        round_rect(
            cr,
            13.0 * scale,
            sweep_y - 5.0 * scale,
            38.0 * scale,
            10.0 * scale,
            5.0 * scale,
        );
        cr.fill();
        set(1.0);
        round_rect(
            cr,
            13.0 * scale,
            sweep_y - 1.0 * scale,
            38.0 * scale,
            2.5 * scale,
            1.5 * scale,
        );
        cr.fill();
    }

    cr.restore();
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
    fn draws_without_panicking() {
        // Paint onto an in-memory surface the way the widget would.
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
