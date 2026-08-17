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
    padding: 10px 26px;
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
    #[allow(dead_code)] // kept for parity with the daemon's enroll fields
    target: Option<usize>,
}

/// The GTK overlay card and its state machine.
pub struct App {
    /// Self handle so timers and button signals can re-borrow the app.
    self_rc: Option<Rc<RefCell<App>>>,
    socket: PathBuf,

    window: gtk::Window,
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
}

impl App {
    /// Build the card and wrap it for shared (re-entrant) use.
    pub fn new(socket: PathBuf) -> Rc<RefCell<App>> {
        let rc = Rc::new(RefCell::new(App {
            self_rc: None,
            socket,
            window: gtk::Window::new(gtk::WindowType::Toplevel),
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
        w.set_size_request(400, -1);
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

        let card = gtk::Box::new(gtk::Orientation::Vertical, 10);
        card.set_widget_name("hiro-card");
        w.add(&card);

        let brand = gtk::Label::new(Some("HIRO"));
        brand.set_widget_name("hiro-brand");
        card.pack_start(&brand, false, false, 0);

        // Content row: animated face + status label.
        let content = gtk::Box::new(gtk::Orientation::Horizontal, 14);
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
        self.status_label.set_widget_name("hiro-label");
        self.status_label.set_xalign(0.0);
        self.status_label.set_wrap(true);
        content.pack_start(&self.face, false, false, 0);
        content.pack_start(&self.status_label, true, true, 0);
        card.pack_start(&content, false, false, 0);

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
        card.pack_start(&self.meter_box, false, false, 0);

        self.hint.set_widget_name("hiro-hint");
        self.hint.set_xalign(0.0);
        card.pack_start(&self.hint, false, false, 0);

        // Approval prompt.
        self.approval_title.set_widget_name("hiro-approval-title");
        self.approval_title.set_wrap(true);
        self.approval_sub.set_widget_name("hiro-approval-sub");
        self.approval_sub.set_wrap(true);
        self.approval_buttons.set_halign(gtk::Align::Center);
        self.approval_buttons.set_spacing(8);
        for btn in [&self.allow_btn, &self.deny_btn] {
            btn.style_context().add_class("hiro-approval-btn");
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
                self.clear_approval();
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
                self.clear_approval();
                self.queue_result(ev);
            }
            _ => {
                // idle or any unknown state: hide everything.
                self.clear_approval();
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
        self.clear_approval();
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
        self.update_scan_label();
        self.face.queue_draw();
        self.start_animations();
        self.show_window();
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
            self.meter_box.set_visible(false);
            self.hint.set_visible(false);
            return;
        };
        let v_ok = v >= mv;
        let m_ok = m >= mm;
        self.variance_bar.set_fraction(bar_fraction(v, mv));
        self.motion_bar.set_fraction(bar_fraction(m, mm));
        set_meter_class(&self.variance_bar, "hiro-meter-var", v_ok);
        set_meter_class(&self.motion_bar, "hiro-meter-mot", m_ok);
        self.hint.set_text(if v_ok && m_ok {
            "Good — hold still"
        } else {
            "Move your head slightly"
        });
        self.meter_box.set_visible(true);
        self.hint.set_visible(true);
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
        self.hint.set_visible(true);
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
        self.pending_result = None;
        self.stop_animations();
        self.meter_box.set_visible(false);
        self.hint.set_visible(false);

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

    fn clear_approval(&mut self) {
        self.stop_approval_timer();
        self.approval = None;
        self.approval_box.set_visible(false);
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
            // any scan, so show the verdict immediately.
            self.cancel_result_timer();
            self.cancel_hide_timer();
            self.stop_animations();
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
                if app.state != "scanning" || app.pending_result.is_none() {
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
        self.meter_box.set_visible(false);
        self.hint.set_visible(false);
        let warn = is_immediate_failure(&r.state, r.reason.as_deref());
        let text = if r.state == "success" {
            if self.enrolling {
                let n = r.accepted.unwrap_or(0);
                format!(
                    "✓ {n} face template{} enrolled",
                    if n == 1 { "" } else { "s" }
                )
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
        self.status_label.set_text(&text);
        self.face_state = if r.state == "success" {
            FaceState::Success
        } else if warn {
            FaceState::Warn
        } else {
            FaceState::Fail
        };
        self.face.queue_draw();
        self.show_window();
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
}

fn bar_fraction(value: f32, max: f32) -> f64 {
    if max <= 0.0 || value.is_nan() {
        return 0.0;
    }
    (value / max).clamp(0.0, 1.0) as f64
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
}
