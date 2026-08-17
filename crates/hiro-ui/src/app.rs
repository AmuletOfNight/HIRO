//! GTK3 overlay card: scanning indicator, approval prompt, result flash.
//!
//! A desktop-agnostic port of the GNOME Shell extension's behaviour: a
//! frameless, always-on-top card centered on the primary monitor that shows
//! live scan progress, Allow/Deny approval buttons (with the countdown and
//! step-away handling), and result flashes.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use glib::ControlFlow;
use gtk::prelude::*;
use gtk::{gdk, glib};

use hiro_core::proto::StateEvent;

use crate::face::{draw_face, FaceState};
use crate::socket;
use crate::state::{is_immediate_failure, reason_label};

/// How long a result stays on screen before the card hides.
const RESULT_MS: u64 = 1600;
/// Minimum time a scan is visible before its result, so a very fast camera
/// match does not flash the "Scanning…" card for a single frame.
const MIN_SCAN_MS: u64 = 480;
/// Debounce for enrollment coaching hint text (matches the extension).
const HINT_DEBOUNCE_MS: u64 = 900;
/// One sweep of the scanning highlight (matches the extension).
const FACE_SCAN_MS: u64 = 1200;
const ANIM_STEP_MS: u64 = 33;
const APPROVAL_TICK_MS: u64 = 250;
const FADE_STEP_MS: u64 = 16;
const FADE_IN_MS: u64 = 150;
const FADE_OUT_MS: u64 = 200;
/// Window resize easing length and step (smooth grow/shrink on content
/// changes, matching the extension's size morph).
const RESIZE_MS: u64 = 200;
const RESIZE_STEP_MS: u64 = 16;
/// Meter fill easing length and step (bars grow instead of snapping).
const FILL_MS: u64 = 200;
const FILL_STEP_MS: u64 = 16;
/// How long the daemon may lag the scan start with liveness telemetry
/// before the (empty) meter tracks are considered pointless and collapsed.
const LIVENESS_GRACE_MS: u128 = 500;

const CSS: &str = r#"
window {
    background-color: #1c2128;
}
#hiro-card {
    background-color: #1c2128;
    border: 1px solid #2d333b;
    border-radius: 16px;
    padding: 18px 26px;
}
#hiro-brand {
    color: #768390;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 3px;
}
#hiro-label {
    color: #c9d1d9;
    font-size: 17px;
    text-align: center;
}
#hiro-hint {
    color: #768390;
    font-size: 14px;
}
#hiro-meter-caption {
    color: #768390;
    font-size: 12px;
}
progressbar.hiro-meter > trough {
    background-color: #2d333b;
    border-radius: 4px;
    min-height: 8px;
}
progressbar.hiro-meter > trough > progress {
    border-radius: 4px;
    min-height: 8px;
}
progressbar.hiro-meter-var > trough > progress { background-color: #ffd166; }
progressbar.hiro-meter-mot > trough > progress { background-color: #4fc3f7; }
progressbar.hiro-meter-ok > trough > progress { background-color: #66bb6a; }
#hiro-approval-title {
    color: #e6edf3;
    font-size: 17px;
    font-weight: bold;
}
#hiro-approval-sub {
    color: #adbac7;
    font-size: 14px;
}
button.hiro-approval-btn {
    border-radius: 8px;
    padding: 12px 0;
    font-weight: bold;
    border: none;
}
button.hiro-allow {
    background-color: #2ea043;
    color: #ffffff;
}
button.hiro-deny {
    background-color: #da3633;
    color: #ffffff;
}
"#;

/// Pending approval prompt state (mirrors the extension's `_approval`).
struct ApprovalState {
    id: u64,
    user: String,
    #[allow(dead_code)]
    service: String,
    secure: bool,
    confidence: String,
    user_present: bool,
    #[allow(dead_code)]
    timeout_ms: u64,
    deadline: Instant,
    countdown_text: String,
}

/// A terminal success/failure event awaiting its on-screen presentation.
struct ResultInfo {
    state: String,
    score: Option<f32>,
    reason: Option<String>,
    accepted: Option<usize>,
    target: Option<usize>,
}

/// The GTK overlay card and its state machine.
pub struct App {
    /// Self handle so timers and button signals can re-borrow the app.
    self_rc: Option<Rc<RefCell<App>>>,
    socket: PathBuf,

    window: gtk::Window,
    card: gtk::Box,
    body: gtk::Box,
    content: gtk::Box,
    side: gtk::Box,
    status_label: gtk::Label,
    face: gtk::DrawingArea,
    meter_box: gtk::Box,
    variance_bar: gtk::ProgressBar,
    motion_bar: gtk::ProgressBar,
    hint: gtk::Label,
    approval_box: gtk::Box,
    approval_title: gtk::Label,
    approval_sub: gtk::Label,
    approval_buttons: gtk::Box,
    allow_btn: gtk::Button,
    deny_btn: gtk::Button,

    // UI state.
    state: String,
    op: String,
    enrolling: bool,
    accepted: Option<usize>,
    target: Option<usize>,
    dots: u32,
    hint_text: Option<String>,
    hint_at: Option<Instant>,
    scan_started_at: Option<Instant>,
    pending_result: Option<ResultInfo>,
    approval: Option<ApprovalState>,

    // Animation.
    sweep: f64,
    breathe: f64,
    anim_phase: u64,
    face_state: FaceState,

    // Timers.
    anim_timer: Option<glib::SourceId>,
    result_timer: Option<glib::SourceId>,
    hide_timer: Option<glib::SourceId>,
    approval_timer: Option<glib::SourceId>,
    fade_timer: Option<glib::SourceId>,
    resize_timer: Option<glib::SourceId>,
    fill_timer_var: Option<glib::SourceId>,
    fill_timer_mot: Option<glib::SourceId>,
    crossfade_timer: Option<glib::SourceId>,
    approval_fade_timer: Option<glib::SourceId>,
}

impl App {
    /// Build the card and wrap it for shared (re-entrant) use.
    pub fn new(socket: PathBuf) -> Rc<RefCell<App>> {
        let rc = Rc::new(RefCell::new(App {
            self_rc: None,
            socket,
            window: gtk::Window::new(gtk::WindowType::Toplevel),
            card: gtk::Box::new(gtk::Orientation::Vertical, 10),
            body: gtk::Box::new(gtk::Orientation::Vertical, 8),
            content: gtk::Box::new(gtk::Orientation::Horizontal, 14),
            side: gtk::Box::new(gtk::Orientation::Vertical, 8),
            status_label: gtk::Label::new(None),
            face: gtk::DrawingArea::new(),
            meter_box: gtk::Box::new(gtk::Orientation::Vertical, 4),
            variance_bar: gtk::ProgressBar::new(),
            motion_bar: gtk::ProgressBar::new(),
            hint: gtk::Label::new(None),
            approval_box: gtk::Box::new(gtk::Orientation::Vertical, 6),
            approval_title: gtk::Label::new(None),
            approval_sub: gtk::Label::new(None),
            approval_buttons: gtk::Box::new(gtk::Orientation::Horizontal, 8),
            allow_btn: gtk::Button::with_label("Allow"),
            deny_btn: gtk::Button::with_label("Deny"),
            state: "idle".into(),
            op: "verify".into(),
            enrolling: false,
            accepted: None,
            target: None,
            dots: 0,
            hint_text: None,
            hint_at: None,
            scan_started_at: None,
            pending_result: None,
            approval: None,
            sweep: 0.0,
            breathe: 1.0,
            anim_phase: 0,
            face_state: FaceState::Idle,
            anim_timer: None,
            result_timer: None,
            hide_timer: None,
            approval_timer: None,
            fade_timer: None,
            resize_timer: None,
            fill_timer_var: None,
            fill_timer_mot: None,
            crossfade_timer: None,
            approval_fade_timer: None,
        }));
        rc.borrow_mut().self_rc = Some(rc.clone());
        rc.borrow_mut().build();
        rc
    }

    fn rc(&self) -> Rc<RefCell<App>> {
        self.self_rc.clone().expect("App self_rc unset")
    }

    /// Construct the widget tree and wire signals.
    fn build(&mut self) {
        let provider = gtk::CssProvider::new();
        if let Err(e) = provider.load_from_data(CSS.as_bytes()) {
            log::warn!("hiro-ui: css load failed: {e}");
        }
        if let Some(screen) = gdk::Screen::default() {
            gtk::StyleContext::add_provider_for_screen(
                &screen,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }

        let w = &self.window;
        w.set_title("HIRO");
        w.set_decorated(false);
        w.set_skip_taskbar_hint(true);
        w.set_skip_pager_hint(true);
        w.set_keep_above(true);
        w.set_type_hint(gdk::WindowTypeHint::Dialog);
        w.set_accept_focus(false);
        w.set_resizable(false);
        w.set_size_request(460, -1);
        w.set_opacity(0.0);
        {
            // Keep the card centered on the primary monitor whenever its
            // size changes (e.g. the meters/approval box appear).
            w.connect_size_allocate(move |win, alloc| {
                if let Some(display) = gdk::Display::default() {
                    if let Some(monitor) = display.primary_monitor() {
                        let geo = monitor.geometry();
                        let x = ((geo.width() - alloc.width()) / 2).max(0);
                        let y = ((geo.height() - alloc.height()) / 2).max(0);
                        win.move_(x, y);
                    }
                }
            });
        }

        let card = &self.card;
        card.set_widget_name("hiro-card");
        w.add(card);

        let brand = gtk::Label::new(Some("HIRO"));
        brand.set_widget_name("hiro-brand");
        card.pack_start(&brand, false, false, 0);

        // Body (crossfaded as a unit on result transitions): the status
        // label on top, then the face with the liveness meters beside it.
        let body = &self.body;
        self.status_label.set_widget_name("hiro-label");
        // Fill the card width so the text block keeps its size whether it
        // reads "Scanning your face…" or "✓ Verified (97%)"; text centres.
        self.status_label.set_xalign(0.5);
        self.status_label.set_halign(gtk::Align::Fill);
        self.status_label.set_wrap(true);
        body.pack_start(&self.status_label, false, false, 0);

        // Content row: animated face + side column (meters, hint).
        let content = &self.content;
        content.set_halign(gtk::Align::Center);
        self.face.set_size_request(96, 96);
        {
            let face_app = self.rc();
            self.face.connect_draw(move |area, cr| {
                let app = face_app.borrow();
                draw_face(
                    cr,
                    area.allocated_width() as f64,
                    area.allocated_height() as f64,
                    app.face_state,
                    app.sweep,
                    app.breathe,
                );
                glib::Propagation::Proceed
            });
        }
        content.pack_start(&self.face, false, false, 0);

        // Liveness meters.
        self.meter_box.pack_start(
            &self.meter_row("Scene motion", &self.variance_bar, "hiro-meter-var"),
            false,
            false,
            0,
        );
        self.meter_box.pack_start(
            &self.meter_row("Head motion", &self.motion_bar, "hiro-meter-mot"),
            false,
            false,
            0,
        );

        self.hint.set_widget_name("hiro-hint");
        self.hint.set_xalign(0.0);
        let side = &self.side;
        side.pack_start(&self.meter_box, false, false, 0);
        side.pack_start(&self.hint, false, false, 0);
        content.pack_start(side, false, false, 0);

        body.pack_start(content, false, false, 0);
        card.pack_start(body, false, false, 0);

        // Approval prompt.
        self.approval_title.set_widget_name("hiro-approval-title");
        self.approval_title.set_wrap(true);
        self.approval_sub.set_widget_name("hiro-approval-sub");
        self.approval_sub.set_wrap(true);
        self.approval_buttons.set_halign(gtk::Align::Fill);
        self.approval_buttons.set_spacing(8);
        for btn in [&self.allow_btn, &self.deny_btn] {
            btn.style_context().add_class("hiro-approval-btn");
            // Each button takes exactly half the dialog width, spanning the
            // full bottom of the card.
            btn.set_hexpand(true);
        }
        self.allow_btn.style_context().add_class("hiro-allow");
        self.deny_btn.style_context().add_class("hiro-deny");
        self.approval_buttons
            .pack_start(&self.allow_btn, false, false, 0);
        self.approval_buttons
            .pack_start(&self.deny_btn, false, false, 0);
        self.approval_box
            .pack_start(&self.approval_title, false, false, 0);
        self.approval_box
            .pack_start(&self.approval_sub, false, false, 0);
        self.approval_box
            .pack_start(&self.approval_buttons, false, false, 0);
        card.pack_start(&self.approval_box, false, false, 0);

        {
            let rc = self.rc();
            let allow_rc = rc.clone();
            let deny_rc = rc.clone();
            self.allow_btn.connect_clicked(move |_| {
                allow_rc.borrow_mut().decide_approval(true);
            });
            self.deny_btn.connect_clicked(move |_| {
                deny_rc.borrow_mut().decide_approval(false);
            });
        }

        self.meter_box.set_visible(false);
        self.hint.set_visible(false);
        self.approval_box.set_visible(false);
        self.approval_buttons.set_visible(false);
        w.show_all();
        w.hide();
    }

    fn meter_row(&self, caption: &str, bar: &gtk::ProgressBar, class: &str) -> gtk::Box {
        let cap = gtk::Label::new(Some(caption));
        cap.set_widget_name("hiro-meter-caption");
        cap.set_xalign(0.0);
        cap.set_width_chars(12);
        bar.set_show_text(false);
        bar.set_hexpand(true);
        bar.set_size_request(190, -1);
        bar.style_context().add_class("hiro-meter");
        bar.style_context().add_class(class);
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.pack_start(&cap, false, false, 0);
        row.pack_start(bar, true, true, 0);
        row
    }

    // --- Event entry points (called from the GTK main loop) ---

    /// Handle a `StateEvent` broadcast from the daemon.
    pub fn on_event(&mut self, ev: &StateEvent) {
        self.op = if ev.op == "enroll" {
            "enroll".into()
        } else {
            "verify".into()
        };
        self.enrolling = self.op == "enroll";
        match ev.state.as_str() {
            "approval_pending" => self.show_approval(ev),
            "scanning" => {
                self.clear_approval(true);
                self.cancel_result_timer();
                self.pending_result = None;
                self.cancel_hide_timer();
                let entering = self.state != "scanning" || self.scan_started_at.is_none();
                if entering {
                    self.enter_scanning();
                }
                if self.enrolling {
                    self.set_enroll_progress(ev.accepted, ev.target);
                    self.set_enroll_hint(ev.reason.as_deref());
                } else {
                    self.update_liveness(ev.variance, ev.motion, ev.min_variance, ev.min_motion);
                }
            }
            "success" | "failure" => {
                // Keep the approval box visible so the result transition can
                // fade it out and morph the window smoothly.
                self.clear_approval(false);
                self.queue_result(ev);
            }
            _ => {
                // idle or any unknown state: hide everything.
                self.clear_approval(true);
                self.cancel_result_timer();
                self.cancel_hide_timer();
                self.pending_result = None;
                self.stop_animations();
                self.state = ev.state.clone();
                self.enrolling = false;
                self.accepted = None;
                self.target = None;
                self.meter_box.set_visible(false);
                self.hint.set_visible(false);
                self.hide_window();
            }
        }
    }

    /// The daemon socket went away; hide any stale UI.
    pub fn on_disconnected(&mut self) {
        log::debug!("daemon unreachable; hiding UI");
        self.clear_approval(true);
        self.cancel_result_timer();
        self.cancel_hide_timer();
        self.pending_result = None;
        self.stop_animations();
        self.hide_window();
    }

    // --- Scanning indicator ---

    fn enter_scanning(&mut self) {
        self.state = "scanning".into();
        self.scan_started_at = Some(Instant::now());
        self.face_state = if self.enrolling {
            FaceState::Enrolling
        } else {
            FaceState::Scanning
        };
        self.set_accept_focus(false);
        self.cancel_crossfade(); // a result crossfade must not bleed into the scan
        self.cancel_approval_fade();
        self.reset_result_layout();
        self.update_scan_label();
        self.face.queue_draw();
        self.start_animations();
        // Show the (empty) meter tracks from the first frame so the card's
        // layout is stable while the bars fill in; enrollment has none.
        if self.enrolling {
            self.meter_box.set_visible(false);
            self.hint.set_visible(false);
        } else {
            self.meter_box.set_visible(true);
            self.hint.set_visible(true);
        }
        self.show_window();
        self.animate_to_natural_size();
    }

    fn update_scan_label(&mut self) {
        let dots = ".".repeat(self.dots as usize);
        if self.enrolling {
            let progress = match (self.accepted, self.target) {
                (Some(a), Some(t)) => format!(" ({a}/{t})"),
                _ => String::new(),
            };
            self.status_label
                .set_text(&format!("Enrolling your face{progress}{dots}"));
        } else {
            self.status_label
                .set_text(&format!("Scanning your face{dots}"));
        }
    }

    fn update_liveness(
        &mut self,
        variance: Option<f32>,
        motion: Option<f32>,
        min_variance: Option<f32>,
        min_motion: Option<f32>,
    ) {
        let Some((v, m, mv, mm)) = variance
            .zip(motion)
            .zip(min_variance)
            .zip(min_motion)
            .map(|(((v, m), mv), mm)| (v, m, mv, mm))
        else {
            // The meters are shown empty from the first scanning frame
            // (enter_scanning). Telemetry may lag the scan start by a few
            // frames; only collapse the tracks once it is clear liveness is
            // disabled and no data will ever arrive.
            let past_grace = self
                .scan_started_at
                .map(|t| t.elapsed().as_millis() >= LIVENESS_GRACE_MS)
                .unwrap_or(true);
            if past_grace {
                self.meter_box.set_visible(false);
                self.hint.set_visible(false);
                self.animate_to_natural_size();
            }
            return;
        };
        let v_ok = v >= mv;
        let m_ok = m >= mm;
        animate_fraction(
            &self.variance_bar,
            bar_fraction(v, mv),
            &mut self.fill_timer_var,
        );
        animate_fraction(
            &self.motion_bar,
            bar_fraction(m, mm),
            &mut self.fill_timer_mot,
        );
        set_meter_class(&self.variance_bar, "hiro-meter-var", v_ok);
        set_meter_class(&self.motion_bar, "hiro-meter-mot", m_ok);
        self.hint.set_text(if v_ok && m_ok {
            "Good — hold still"
        } else {
            "Move your head slightly"
        });
    }

    fn set_enroll_progress(&mut self, accepted: Option<usize>, target: Option<usize>) {
        if accepted.is_some() {
            self.accepted = accepted;
        }
        if target.is_some() {
            self.target = target;
        }
        self.update_scan_label();
    }

    /// Live coaching hint during enrollment; debounced like the extension.
    fn set_enroll_hint(&mut self, reason: Option<&str>) {
        let Some(hint) = reason.and_then(|r| reason_label(Some(r))) else {
            // reason == None means a frame was accepted: keep the last
            // hint stable instead of blinking it away.
            return;
        };
        let now = Instant::now();
        let debounced = self.hint_text.as_ref() == Some(&hint)
            || (self.hint.is_visible()
                && self
                    .hint_at
                    .map(|t| (now.duration_since(t).as_millis() as u64) < HINT_DEBOUNCE_MS)
                    .unwrap_or(false));
        if !debounced {
            self.hint.set_text(&hint);
            self.hint_text = Some(hint);
            self.hint_at = Some(now);
        }
        let became_visible = !self.hint.is_visible();
        self.hint.set_visible(true);
        // Growing the side column (hint appears) morphs the card size.
        if became_visible {
            self.animate_to_natural_size();
        }
    }

    fn start_animations(&mut self) {
        if self.anim_timer.is_some() {
            return;
        }
        let rc = self.rc();
        self.anim_timer = Some(glib::timeout_add_local(
            Duration::from_millis(ANIM_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                if app.state != "scanning" {
                    app.stop_animations();
                    return ControlFlow::Break;
                }
                app.anim_phase = app.anim_phase.wrapping_add(ANIM_STEP_MS);
                let period = app.anim_phase % FACE_SCAN_MS;
                let p = period as f64 / FACE_SCAN_MS as f64;
                app.sweep = (p * std::f64::consts::PI).sin();
                app.breathe = 1.0 + 0.04 * (p * 2.0 * std::f64::consts::PI).sin();
                app.dots = (app.anim_phase / 500) as u32 % 4 + 1;
                app.update_scan_label();
                app.face.queue_draw();
                ControlFlow::Continue
            },
        ));
    }

    fn stop_animations(&mut self) {
        if let Some(id) = self.anim_timer.take() {
            id.remove();
        }
        self.sweep = 0.0;
        self.breathe = 1.0;
    }

    // --- Approval prompt ---

    fn show_approval(&mut self, ev: &StateEvent) {
        self.cancel_result_timer();
        self.cancel_hide_timer();
        self.cancel_crossfade();
        self.reset_result_layout();
        self.pending_result = None;
        self.stop_animations();
        // Keep the meter tracks in the layout (the card keeps the scan card's
        // width) but fade them out and glide the smiley to the centre, so the
        // approval card already has the face position the verified card will
        // use.

        let svc = ev
            .service
            .clone()
            .unwrap_or_else(|| "this application".into());
        let confidence = match ev.score {
            Some(s) => format!("Match {:.0}%", s * 100.0),
            None => "Face recognized".into(),
        };
        let id = ev.approval_id.unwrap_or(0);

        // Same approval re-broadcast (the user stepped in/out of the
        // frame): update presence only, keep the parked request intact.
        if let Some(a) = &self.approval {
            if a.id == id {
                self.approval.as_mut().unwrap().user_present = ev.user_present != Some(false);
                self.update_approval_buttons();
                self.animate_to_natural_size();
                return;
            }
        }

        self.state = "approval_pending".into();
        self.face_state = FaceState::Approval;
        self.face.queue_draw();
        self.status_label.set_text("Approve this action?");
        self.approval_title.set_text(&format!(
            "{svc} wants to authenticate as {}",
            ev.user.as_deref().unwrap_or("you")
        ));
        self.approval = Some(ApprovalState {
            id,
            user: ev.user.clone().unwrap_or_default(),
            service: svc,
            secure: ev.secure == Some(true),
            confidence,
            user_present: ev.user_present != Some(false),
            timeout_ms: ev.approval_timeout_ms.unwrap_or(0),
            deadline: Instant::now()
                + Duration::from_millis(ev.approval_timeout_ms.unwrap_or(5000)),
            countdown_text: String::new(),
        });
        self.approval_box.set_visible(true);
        self.set_accept_focus(true);
        self.update_approval_buttons();
        self.start_approval_timer();
        self.show_window();
        // Fade the meters/hint out in place and glide the smiley to the
        // centre, then grow the card to include the prompt.
        self.settle_side_and_center_face();
        self.animate_to_natural_size();
    }

    fn update_approval_buttons(&mut self) {
        let Some(a) = &self.approval else {
            return;
        };
        if a.secure {
            self.approval_buttons.set_visible(false);
            self.approval_sub.set_text("decide on the secure console");
        } else if !a.user_present {
            self.approval_buttons.set_visible(false);
            self.approval_sub
                .set_text("Step back in front of the camera to approve");
        } else {
            self.approval_buttons.set_visible(true);
            let sub = if a.countdown_text.is_empty() {
                a.confidence.clone()
            } else {
                a.countdown_text.clone()
            };
            self.approval_sub.set_text(&sub);
        }
    }

    fn start_approval_timer(&mut self) {
        if self.approval_timer.is_some() {
            return;
        }
        let rc = self.rc();
        self.approval_timer = Some(glib::timeout_add_local(
            Duration::from_millis(APPROVAL_TICK_MS),
            move || {
                let mut app = rc.borrow_mut();
                let Some(a) = app.approval.as_ref() else {
                    app.approval_timer = None;
                    return ControlFlow::Break;
                };
                let remaining = a.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    app.approval_timer = None;
                    app.expire_approval();
                    return ControlFlow::Break;
                }
                let secs = remaining.as_millis().div_ceil(1000) as u64;
                let (secure, present) = (a.secure, a.user_present);
                if !secure && present {
                    let conf = a.confidence.clone();
                    app.approval.as_mut().unwrap().countdown_text =
                        format!("{conf} · {secs}s to decide");
                }
                app.update_approval_buttons();
                ControlFlow::Continue
            },
        ));
    }

    fn stop_approval_timer(&mut self) {
        if let Some(id) = self.approval_timer.take() {
            id.remove();
        }
    }

    fn expire_approval(&mut self) {
        self.approval_buttons.set_visible(false);
        self.approval_sub
            .set_text("Decision window closed — request not approved");
    }

    fn decide_approval(&mut self, allow: bool) {
        let Some(a) = &self.approval else {
            return;
        };
        if a.secure || !a.user_present {
            return;
        }
        let id = a.id;
        let user = a.user.clone();
        self.stop_approval_timer();
        self.approval_buttons.set_visible(false);
        self.approval_sub
            .set_text(if allow { "Allowing…" } else { "Denying…" });
        // Fire-and-forget on a worker thread so a wedged daemon never
        // freezes the UI; the daemon broadcasts the terminal event which
        // drives the actual result display.
        let socket = self.socket.clone();
        std::thread::spawn(move || {
            socket::approve(&socket, id, &user, allow);
        });
    }

    fn clear_approval(&mut self, hide_box: bool) {
        self.stop_approval_timer();
        self.cancel_approval_fade();
        self.approval = None;
        // When hide_box is false the box is left visible so the result
        // transition can fade it out smoothly.
        if hide_box {
            self.approval_box.set_visible(false);
        }
        self.approval_buttons.set_visible(false);
        self.set_accept_focus(false);
    }

    // --- Results ---

    fn queue_result(&mut self, ev: &StateEvent) {
        let result = ResultInfo {
            state: ev.state.clone(),
            score: ev.score,
            reason: ev.reason.clone(),
            accepted: ev.accepted,
            target: ev.target,
        };
        if is_immediate_failure(&result.state, result.reason.as_deref()) {
            // Rate-limited / locked-out / password-required: rejected before
            // any scan, so show the verdict immediately as a compact card
            // (no meter tracks).
            self.cancel_result_timer();
            self.cancel_hide_timer();
            self.stop_animations();
            self.meter_box.set_visible(false);
            self.hint.set_visible(false);
            self.state = result.state.clone();
            self.pending_result = Some(result);
            self.present_result();
            return;
        }
        let was_approving = self.state == "approval_pending";
        if (self.state != "scanning" || self.scan_started_at.is_none()) && !was_approving {
            self.enter_scanning(); // brief "scanning" flash before the verdict
        }
        self.pending_result = Some(result);
        self.cancel_result_timer();
        let elapsed = self
            .scan_started_at
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let wait = MIN_SCAN_MS.saturating_sub(elapsed);
        if wait == 0 {
            self.present_result();
            return;
        }
        let rc = self.rc();
        self.result_timer = Some(glib::timeout_add_local(
            Duration::from_millis(wait),
            move || {
                let mut app = rc.borrow_mut();
                app.result_timer = None;
                // The result may arrive while an approval prompt is up
                // (Allow/Deny clicked, or the decision window expired); both
                // 'scanning' and 'approval_pending' are valid pre-result states.
                if (app.state != "scanning" && app.state != "approval_pending")
                    || app.pending_result.is_none()
                {
                    return ControlFlow::Break;
                }
                app.present_result();
                ControlFlow::Break
            },
        ));
    }

    fn present_result(&mut self) {
        let Some(r) = self.pending_result.take() else {
            return;
        };
        self.state = r.state.clone();
        self.stop_animations();
        // The meters/hint stay visible here; the in-place result transition
        // fades them out (and a compact verdict never showed them).
        let warn = is_immediate_failure(&r.state, r.reason.as_deref());
        let text = if r.state == "success" {
            if self.enrolling {
                let n = r.accepted.unwrap_or(0);
                let plural = if n == 1 { "" } else { "s" };
                if r.reason.as_deref() == Some("insufficient_templates") {
                    // The run succeeded but the user still sits below the
                    // minimum distinct-pose count: keep the success frame
                    // and nudge them to run enrollment again.
                    let missing = r.target.unwrap_or(n).saturating_sub(n);
                    format!(
                        "✓ {n} face template{plural} enrolled — {missing} more pose{} needed",
                        if missing == 1 { "" } else { "s" }
                    )
                } else {
                    format!("✓ {n} face template{plural} enrolled")
                }
            } else {
                let score = r
                    .score
                    .map(|s| format!(" ({:.0}%)", s * 100.0))
                    .unwrap_or_default();
                format!("✓  Verified{score}")
            }
        } else {
            reason_label(r.reason.as_deref()).unwrap_or_else(|| {
                if self.enrolling {
                    "Face enrollment failed".to_string()
                } else {
                    "Not recognized".to_string()
                }
            })
        };
        let face_state = if r.state == "success" {
            FaceState::Success
        } else if warn {
            FaceState::Warn
        } else {
            FaceState::Fail
        };
        self.show_window();
        // If an approval prompt was up, fade it out and let the window
        // settle to the result size instead of snapping.
        if self.approval_box.is_visible() {
            self.fade_out_approval_box();
        }
        // A scan that was showing its meter tracks morphs in place: the card
        // keeps its width, the bars fade out and the smiley glides to the
        // centre while turning the result colour. A compact verdict (no scan
        // happened) just crossfades and shrinks to fit.
        if self.meter_box.is_visible() {
            self.transition_to_result(text, face_state);
        } else {
            self.crossfade_result(text, face_state);
            self.animate_to_natural_size();
        }
        self.schedule_hide(RESULT_MS);
    }

    fn schedule_hide(&mut self, ms: u64) {
        self.cancel_hide_timer();
        let rc = self.rc();
        self.hide_timer = Some(glib::timeout_add_local(
            Duration::from_millis(ms),
            move || {
                let mut app = rc.borrow_mut();
                app.hide_timer = None;
                if app.state != "success" && app.state != "failure" {
                    return ControlFlow::Break;
                }
                app.hide_window();
                ControlFlow::Break
            },
        ));
    }

    fn cancel_result_timer(&mut self) {
        if let Some(id) = self.result_timer.take() {
            id.remove();
        }
    }

    fn cancel_hide_timer(&mut self) {
        if let Some(id) = self.hide_timer.take() {
            id.remove();
        }
    }

    // --- Window visibility ---

    fn set_accept_focus(&mut self, accept: bool) {
        self.window.set_accept_focus(accept);
    }

    fn show_window(&mut self) {
        self.cancel_fade();
        if self.window.is_visible() {
            self.window.set_opacity(1.0);
            return;
        }
        self.window.show();
        self.window.set_opacity(0.0);
        let rc = self.rc();
        let start = Instant::now();
        self.fade_timer = Some(glib::timeout_add_local(
            Duration::from_millis(FADE_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                let t = start.elapsed().as_secs_f64() / (FADE_IN_MS as f64 / 1000.0);
                if t >= 1.0 {
                    app.window.set_opacity(1.0);
                    app.fade_timer = None;
                    return ControlFlow::Break;
                }
                app.window.set_opacity(t);
                ControlFlow::Continue
            },
        ));
    }

    fn hide_window(&mut self) {
        self.cancel_fade();
        self.cancel_resize_animation();
        self.cancel_crossfade();
        self.cancel_approval_fade();
        self.reset_result_layout();
        if !self.window.is_visible() {
            return;
        }
        let rc = self.rc();
        let start = Instant::now();
        self.fade_timer = Some(glib::timeout_add_local(
            Duration::from_millis(FADE_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                let t = start.elapsed().as_secs_f64() / (FADE_OUT_MS as f64 / 1000.0);
                if t >= 1.0 {
                    app.fade_timer = None;
                    app.window.hide();
                    app.window.set_opacity(1.0); // reset for the next fade-in
                    return ControlFlow::Break;
                }
                app.window.set_opacity(1.0 - t);
                ControlFlow::Continue
            },
        ));
    }

    fn cancel_fade(&mut self) {
        if let Some(id) = self.fade_timer.take() {
            id.remove();
        }
    }

    // --- Smooth resize and content transitions ---

    /// Ease the window from its current size to the card's natural size so
    /// it grows/shrinks smoothly when content appears or disappears. The
    /// size-allocate hook re-centres on the primary monitor at every step,
    /// so the growth stays symmetric. Interruptible: a newer request
    /// cancels the in-flight animation and restarts from the current size.
    fn animate_to_natural_size(&mut self) {
        self.cancel_resize_animation();
        let (_, natural) = self.card.preferred_size();
        let target_w = natural.width.max(460);
        let target_h = natural.height;
        let (cur_w, cur_h) = self.window.size();
        if (cur_w - target_w).abs() < 2 && (cur_h - target_h).abs() < 2 {
            return;
        }
        // Re-assert the current size so GTK's own resize-on-request-change
        // (triggered by the size-request change) cannot snap the window to
        // the target before the easing below takes over.
        self.window.resize(cur_w, cur_h);
        let rc = self.rc();
        let start = Instant::now();
        self.resize_timer = Some(glib::timeout_add_local(
            Duration::from_millis(RESIZE_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                let t = (start.elapsed().as_secs_f64() / (RESIZE_MS as f64 / 1000.0)).min(1.0);
                let e = ease_out_quad(t);
                let w = (cur_w as f64 + (target_w - cur_w) as f64 * e).round() as i32;
                let h = (cur_h as f64 + (target_h - cur_h) as f64 * e).round() as i32;
                app.window.resize(w, h);
                if t >= 1.0 {
                    app.resize_timer = None;
                    return ControlFlow::Break;
                }
                ControlFlow::Continue
            },
        ));
    }

    fn cancel_resize_animation(&mut self) {
        if let Some(id) = self.resize_timer.take() {
            id.remove();
        }
    }

    /// Crossfade the card body to a result: fade the old content out, swap
    /// in the verdict text/face, fade back in. Matches the extension's
    /// `_transitionToResult`; the window shrink happens in parallel via
    /// `animate_to_natural_size`.
    fn crossfade_result(&mut self, text: String, face_state: FaceState) {
        self.cancel_crossfade();
        // Compact verdicts (no scan / no meters): start from a clean layout.
        self.reset_result_layout();
        let rc = self.rc();
        let phase = Rc::new(RefCell::new(0u8));
        let phase_start = Rc::new(RefCell::new(Instant::now()));
        self.crossfade_timer = Some(glib::timeout_add_local(
            Duration::from_millis(FADE_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                let mut phase = phase.borrow_mut();
                let mut phase_start = phase_start.borrow_mut();
                if *phase == 0 {
                    // Fade the old content out, then swap in the result.
                    let t = phase_start.elapsed().as_secs_f64()
                        / (FADE_OUT_MS as f64 / 1000.0);
                    if t < 1.0 {
                        app.body.set_opacity(1.0 - t);
                        return ControlFlow::Continue;
                    }
                    app.body.set_opacity(0.0);
                    app.status_label.set_text(&text);
                    app.face_state = face_state;
                    app.face.queue_draw();
                    // The verdict text is narrower than the scan label, so
                    // re-ease to the final natural size after the swap.
                    app.animate_to_natural_size();
                    *phase = 1;
                    *phase_start = Instant::now();
                    ControlFlow::Continue
                } else {
                    // Fade the result in.
                    let t = phase_start.elapsed().as_secs_f64()
                        / (FADE_IN_MS as f64 / 1000.0);
                    if t < 1.0 {
                        app.body.set_opacity(t);
                        return ControlFlow::Continue;
                    }
                    app.body.set_opacity(1.0);
                    app.crossfade_timer = None;
                    ControlFlow::Break
                }
            },
        ));
    }

    fn cancel_crossfade(&mut self) {
        if let Some(id) = self.crossfade_timer.take() {
            id.remove();
        }
        self.body.set_opacity(1.0);
    }

    /// Undo everything the in-place result transition did (frozen row width,
    /// shifted smiley, transparent meters) so the next state starts clean.
    /// Called at state boundaries, not by cancel_crossfade — the approval →
    /// result flow must keep the face position the approval already set.
    fn reset_result_layout(&mut self) {
        self.body.set_opacity(1.0);
        self.content.set_size_request(-1, -1);
        self.face.set_margin_start(0);
        self.side.set_opacity(1.0);
    }

    /// Freeze the content-row width (the card keeps the scan card's width),
    /// fade the meters/hint out in place, and glide the smiley to the centre.
    /// Shared by the approval and result transitions so the face ends up in
    /// the same place.
    fn settle_side_and_center_face(&mut self) {
        self.cancel_crossfade();
        let (_, nat) = self.content.preferred_size();
        let row_w = nat.width.max(96);
        self.content.set_size_request(row_w, -1);
        let dx = ((row_w as f64 - 96.0) / 2.0).round() as i32;
        let face = self.face.clone();
        let side = self.side.clone();
        let start = Instant::now();
        self.crossfade_timer = Some(glib::timeout_add_local(
            Duration::from_millis(FADE_STEP_MS),
            move || {
                let t = start.elapsed().as_secs_f64() / 0.28;
                let e = ease_in_out_quad(t.min(1.0));
                face.set_margin_start((dx as f64 * e).round() as i32);
                side.set_opacity(1.0 - e);
                if t >= 1.0 {
                    face.set_margin_start(dx);
                    side.set_opacity(0.0);
                    return ControlFlow::Break;
                }
                ControlFlow::Continue
            },
        ));
    }

    /// Fade an up-standing approval prompt out (result arrived), then hide it
    /// and let the window settle to the result size.
    fn fade_out_approval_box(&mut self) {
        if !self.approval_box.is_visible() {
            return;
        }
        self.cancel_approval_fade();
        let rc = self.rc();
        let start = Instant::now();
        let duration = FADE_OUT_MS as f64 / 1000.0;
        self.approval_fade_timer = Some(glib::timeout_add_local(
            Duration::from_millis(FADE_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                let t = start.elapsed().as_secs_f64() / duration;
                if t >= 1.0 {
                    app.approval_box.set_opacity(1.0);
                    app.approval_box.set_visible(false);
                    app.approval_fade_timer = None;
                    // The box is out of the layout now: settle the window.
                    app.animate_to_natural_size();
                    return ControlFlow::Break;
                }
                app.approval_box.set_opacity(1.0 - t);
                ControlFlow::Continue
            },
        ));
    }

    fn cancel_approval_fade(&mut self) {
        if let Some(id) = self.approval_fade_timer.take() {
            id.remove();
        }
        self.approval_box.set_opacity(1.0);
    }

    /// In-place morph of the scanning card to the verdict: the card keeps
    /// its width (the meter rows stay in the layout and fade out), the label
    /// crossfades to the result text, and the smiley glides to the centre
    /// while the face_state swap (result colour) happens under a fade.
    fn transition_to_result(&mut self, text: String, face_state: FaceState) {
        self.cancel_crossfade();
        // Freeze the content-row width so the result card keeps the scan
        // card's dimensions while the meters fade and the smiley slides.
        let (_, nat) = self.content.preferred_size();
        let row_w = nat.width.max(96);
        self.content.set_size_request(row_w, -1);
        let dx = ((row_w as f64 - 96.0) / 2.0).round() as i32;

        let rc = self.rc();
        let phase = Rc::new(RefCell::new(0u8));
        let phase_start = Rc::new(RefCell::new(Instant::now()));
        let start = Rc::new(RefCell::new(Instant::now()));
        let face = self.face.clone();
        // Start the glide from the smiley's current margin (for an approval
        // result it is already centred, so the glide is a no-op).
        let from_margin = self.face.margin_start();
        self.crossfade_timer = Some(glib::timeout_add_local(
            Duration::from_millis(FADE_STEP_MS),
            move || {
                let mut app = rc.borrow_mut();
                let mut phase = phase.borrow_mut();
                let mut phase_start = phase_start.borrow_mut();
                let start = start.borrow_mut();
                // The slide runs continuously from the start (280 ms), so the
                // smiley is still gliding while it fades back in.
                let tween_t = (start.elapsed().as_secs_f64() / 0.28).min(1.0);
                let m = (from_margin as f64 + (dx - from_margin) as f64
                    * ease_in_out_quad(tween_t)).round() as i32;
                face.set_margin_start(m);
                if *phase == 0 {
                    // Fade the old content out (label + face + meters).
                    let t = phase_start.elapsed().as_secs_f64()
                        / (FADE_OUT_MS as f64 / 1000.0);
                    if t < 1.0 {
                        app.body.set_opacity(1.0 - t);
                        return ControlFlow::Continue;
                    }
                    // Swap in the verdict; the meters are gone for good.
                    app.body.set_opacity(0.0);
                    app.status_label.set_text(&text);
                    app.face_state = face_state;
                    app.face.queue_draw();
                    app.side.set_opacity(0.0);
                    *phase = 1;
                    *phase_start = Instant::now();
                    ControlFlow::Continue
                } else {
                    // Fade the verdict back in.
                    let t = phase_start.elapsed().as_secs_f64()
                        / (FADE_IN_MS as f64 / 1000.0);
                    if t < 1.0 {
                        app.body.set_opacity(t);
                        return ControlFlow::Continue;
                    }
                    app.body.set_opacity(1.0);
                    app.crossfade_timer = None;
                    ControlFlow::Break
                }
            },
        ));
    }
}

fn bar_fraction(value: f32, max: f32) -> f64 {
    if max <= 0.0 || value.is_nan() {
        return 0.0;
    }
    (value / max).clamp(0.0, 1.0) as f64
}

/// Ease-out-quad easing, the same shape as Clutter's `EASE_OUT_QUAD` used
/// by the GNOME extension's size morphs.
fn ease_out_quad(t: f64) -> f64 {
    t * (2.0 - t)
}

/// Ease-in-out-quad easing, the same shape as Clutter's `EASE_IN_OUT_QUAD`
/// used by the extension's smiley glide.
fn ease_in_out_quad(t: f64) -> f64 {
    if t < 0.5 {
        2.0 * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(2) / 2.0
    }
}

/// Ease a progress bar toward `target` instead of snapping, so the bars
/// grow smoothly as telemetry streams in. A newer tick cancels the in-flight
/// tween and retargets from the current value.
fn animate_fraction(bar: &gtk::ProgressBar, target: f64, timer: &mut Option<glib::SourceId>) {
    if let Some(id) = timer.take() {
        id.remove();
    }
    let from = bar.fraction();
    if (from - target).abs() < 0.001 {
        return;
    }
    let bar = bar.clone();
    let start = Instant::now();
    *timer = Some(glib::timeout_add_local(
        Duration::from_millis(FILL_STEP_MS),
        move || {
            let t = start.elapsed().as_secs_f64() / (FILL_MS as f64 / 1000.0);
            if t >= 1.0 {
                bar.set_fraction(target);
                return ControlFlow::Break;
            }
            bar.set_fraction(from + (target - from) * ease_out_quad(t));
            ControlFlow::Continue
        },
    ));
}

fn set_meter_class(bar: &gtk::ProgressBar, base: &str, ok: bool) {
    let ctx = bar.style_context();
    for c in ["hiro-meter-var", "hiro-meter-mot", "hiro-meter-ok"] {
        ctx.remove_class(c);
    }
    ctx.add_class(if ok { "hiro-meter-ok" } else { base });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_fraction_clamps() {
        assert_eq!(bar_fraction(0.0, 3.0), 0.0);
        assert_eq!(bar_fraction(3.0, 3.0), 1.0);
        assert_eq!(bar_fraction(1.5, 3.0), 0.5);
        // Clamps beyond the window and rejects degenerate inputs.
        assert_eq!(bar_fraction(9.0, 3.0), 1.0);
        assert_eq!(bar_fraction(1.0, 0.0), 0.0);
        assert_eq!(bar_fraction(1.0, -2.0), 0.0);
        assert_eq!(bar_fraction(f32::NAN, 3.0), 0.0);
    }

    #[test]
    fn approval_countdown_rounds_up() {
        // A 5001 ms window must read "6s to decide" until it dips below
        // 5s; round up so the user is never told "0s" while time remains.
        for (remaining_ms, expected) in [(5_000u64, 5u64), (5_001, 6), (1, 1), (999, 1), (1_000, 1)]
        {
            assert_eq!(remaining_ms.div_ceil(1000), expected, "{remaining_ms}ms");
        }
    }

    #[test]
    fn ease_out_quad_endpoints_and_monotonicity() {
        // Eases from 0 to 1, is monotonic, and starts fast then slows.
        assert_eq!(ease_out_quad(0.0), 0.0);
        assert_eq!(ease_out_quad(1.0), 1.0);
        let mut prev = f64::MIN;
        for i in 0..=100 {
            let t = i as f64 / 100.0;
            let e = ease_out_quad(t);
            assert!(e >= prev, "non-monotonic at t={t}");
            assert!((0.0..=1.0).contains(&e));
            prev = e;
        }
        // Starts decelerating: the midpoint has already covered 3/4.
        assert_eq!(ease_out_quad(0.5), 0.75);
    }

    #[test]
    fn resize_steps_reach_target() {
        // The stepped resize math used by animate_to_natural_size lands on
        // the target after the easing completes.
        let (cur_w, cur_h, target_w, target_h) = (400, 200, 470, 330);
        let mut last = (cur_w, cur_h);
        for i in 0..=64 {
            let t = ((i as f64) * RESIZE_STEP_MS as f64 / 1000.0) / (RESIZE_MS as f64 / 1000.0);
            let t = t.min(1.0);
            let e = ease_out_quad(t);
            last = (
                (cur_w as f64 + (target_w - cur_w) as f64 * e).round() as i32,
                (cur_h as f64 + (target_h - cur_h) as f64 * e).round() as i32,
            );
        }
        assert_eq!(last, (target_w, target_h));
        // And intermediate steps move monotonically toward the target.
        let mut prev = (cur_w, cur_h);
        for i in 0..=20 {
            let t = ((i as f64) * RESIZE_STEP_MS as f64 / 1000.0) / (RESIZE_MS as f64 / 1000.0);
            let e = ease_out_quad(t.min(1.0));
            let step = (
                (cur_w as f64 + (target_w - cur_w) as f64 * e).round() as i32,
                (cur_h as f64 + (target_h - cur_h) as f64 * e).round() as i32,
            );
            assert!(step.0 >= prev.0 && step.1 >= prev.1, "stepped backwards at i={i}");
            prev = step;
        }
    }
}
