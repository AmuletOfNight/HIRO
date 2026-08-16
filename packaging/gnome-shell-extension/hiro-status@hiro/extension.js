/* HIRO Face Auth Status - animated indicator for face scanning. */
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';
import St from 'gi://St';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const SOCKET = '/run/hirod/hirod.sock';
const RESULT_MS = 1600;
const MIN_SCAN_MS = 480;
const TRANSITION_MS = 150;
const POP_IN_MS = 220;
const POP_SETTLE_MS = 120;
const HIDE_MS = 220;

export default class HiroStatusExtension extends Extension {
    enable() {
        this._enabled = true;
        this._state = 'idle';
        this._dots = 0;
        this._retry = null;
        this._dotTimer = null;
        this._resultTimer = null;
        this._hideTimer = null;
        this._pendingResult = null;
        this._scanStartedAt = 0;
        this._animationToken = 0;
        this._pulseToken = 0;
        this._connection = null;
        this._readLoop = null;

        // Top-bar indicator button.
        this._indicator = new PanelMenu.Button(0.0, 'HIRO face auth', true);
        this._icon = new St.Icon({
            icon_name: 'camera-photo-symbolic',
            style_class: 'system-status-icon',
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._indicator.add_child(this._icon);
        this._indicator.visible = true;
        this._setConnected(false);
        Main.panel.addToStatusArea('hiro-status', this._indicator, 1, 'right');

        // Centered overlay with the animated "scanning" message. Lives in
        // the overlay layer when available so it also renders above the
        // screen shield; falls back to the main UI group otherwise.
        this._overlay = new St.Bin({
            style_class: 'hiro-status-overlay',
            reactive: false,
            visible: false,
            x_expand: true,
            y_expand: true,
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.START,
        });
        this._overlay.set_translation(0, 18, 0);
        this._overlay.set_pivot_point(0.5, 0.5);
        this._box = new St.BoxLayout({style_class: 'hiro-status-box', vertical: false});
        this._boxIcon = new St.Icon({icon_name: 'camera-photo-symbolic', icon_size: 40});
        this._label = new St.Label({
            text: 'Scanning your face',
            style_class: 'hiro-status-label',
        });
        this._box.add_child(this._boxIcon);
        this._box.add_child(this._label);
        this._overlay.set_child(this._box);
        const overlayParent = Main.layoutManager.overlayGroup ?? Main.uiGroup;
        overlayParent.add_child(this._overlay);

        this._connect();
        this._retry = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 3, () => {
            if (!this._connected) this._connect();
            return true;
        });
    }

    disable() {
        this._enabled = false;
        this._stopAnimations();
        this._cancelOverlayAnimation();
        if (this._dotTimer) GLib.source_remove(this._dotTimer);
        if (this._retry) GLib.source_remove(this._retry);
        this._dotTimer = null;
        this._retry = null;
        this._cancelResultTimer();
        this._cancelHideTimer();
        if (this._connection) this._connection.close(null);
        this._connection = null;
        this._connected = false;
        if (this._overlay) this._overlay.destroy();
        if (this._indicator) this._indicator.destroy();
        this._overlay = null;
        this._indicator = null;
        this._icon = null;
    }

    _setConnected(connected) {
        this._connected = connected;
        if (!this._icon) return;
        this._icon.icon_name = connected ? 'face-recognition-symbolic' : 'camera-photo-symbolic';
        this._icon.tooltip_text = connected ? 'HIRO connected' : 'HIRO: daemon not reachable';
    }

    _connect() {
        if (!this._enabled || this._connected) return;
        try {
            // Keep the client referenced too; GJS finalizers can otherwise
            // tear down the socket it produced.
            this._client = new Gio.SocketClient({timeout: 2});
            const addr = Gio.UnixSocketAddress.new(SOCKET);
            this._connection = this._client.connect(addr, null);
        } catch (e) {
            console.log(`hiro-status: connect error: ${e?.message}`);
            this._setConnected(false);
            return;
        }
        this._setConnected(true);
        if (!this._enabled || !this._icon) return;
        this._icon.style_class = 'system-status-icon';
        try {
            // Keep a reference to the output stream: if it gets garbage
            // collected, finalizing it closes the socket connection.
            this._out = new Gio.DataOutputStream({
                base_stream: this._connection.get_output_stream(),
            });
            this._out.put_string('{"v":1,"id":0,"op":"watch"}\n', null);
        } catch (e) {
            console.log(`hiro-status: write error: ${e?.message}`);
            this._setConnected(false);
            return;
        }
        this._input = new Gio.DataInputStream({
            base_stream: this._connection.get_input_stream(),
        });
        const readAsync = () => {
            if (!this._connection) return;
            try {
                this._input.read_line_async(GLib.PRIORITY_DEFAULT, null, (src, res) => {
                    try {
                        // read_line_finish varies by GJS/GLib: a string, a
                        // Uint8Array, or a [bytes, length] tuple.
                        let result = src.read_line_finish(res);
                        if (Array.isArray(result)) {
                            result = result[0];
                        }
                        if (result === null) {
                            console.log('hiro-status: eof (daemon closed connection)');
                            this._setConnected(false);
                            return;
                        }
                        let text;
                        if (typeof result === 'string') {
                            text = result;
                        } else if (result instanceof Uint8Array) {
                            text = new TextDecoder().decode(result);
                        } else {
                            console.log(`hiro-status: unexpected line type: ${typeof result}`);
                            text = String(result);
                        }
                        try {
                            const ev = JSON.parse(text);
                            if (ev.state) this.setState(ev.state, ev.score, ev.reason);
                        } catch (e) {
                            console.log(`hiro-status: parse error: ${e?.message}`);
                        }
                        readAsync();
                    } catch (e) {
                        console.log(`hiro-status: read error: ${e?.message}`);
                        this._setConnected(false);
                    }
                });
            } catch (e) {
                console.log(`hiro-status: async error: ${e?.message}`);
                this._setConnected(false);
            }
        };
        readAsync();
    }

    setState(state, score, reason) {
        if (!this._enabled || !this._overlay || !this._icon) return;
        console.log(`hiro-status: state=${state} score=${score} reason=${reason}`);
        if (state === 'scanning') {
            this._cancelResultTimer();
            this._pendingResult = null;
            const enteringScanning = this._state !== 'scanning' || !this._overlay.visible;
            if (enteringScanning) {
                this._state = 'scanning';
                this._scanStartedAt = GLib.get_monotonic_time();
                this._cancelOverlayAnimation();
            }
            this._cancelHideTimer();
            this._icon.style_class = 'system-status-icon hiro-scanning';
            this._startPulse();
            this._startDots();
            this._showOverlay('Scanning your face', 'camera-photo-symbolic', null, enteringScanning);
        } else if (state === 'success') {
            this._queueResult(state, score, reason);
        } else if (state === 'failure') {
            this._queueResult(state, score, reason);
        } else {
            this._cancelResultTimer();
            this._pendingResult = null;
            this._cancelHideTimer();
            this._state = state;
            this._stopAnimations();
            this._cancelOverlayAnimation();
            this._animateOverlayOut(() => {
                if (this._state === state) this._icon.style_class = 'system-status-icon';
            });
        }
    }

    _queueResult(state, score, reason) {
        // A very fast camera match can otherwise replace the scan message
        // before it has rendered for long enough to be useful.
        if (this._state !== 'scanning' || !this._scanStartedAt) {
            this._state = 'scanning';
            this._scanStartedAt = GLib.get_monotonic_time();
            this._cancelHideTimer();
            this._cancelOverlayAnimation();
            this._icon.style_class = 'system-status-icon hiro-scanning';
            this._startPulse();
            this._startDots();
            this._showOverlay('Scanning your face', 'camera-photo-symbolic', null, true);
        }

        this._pendingResult = {state, score, reason};
        this._cancelResultTimer();
        const elapsedMs = (GLib.get_monotonic_time() - this._scanStartedAt) / 1000;
        const waitMs = Math.ceil(Math.max(0, MIN_SCAN_MS - elapsedMs));
        if (waitMs === 0) {
            this._presentResult();
            return;
        }

        this._resultTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, waitMs, () => {
            this._resultTimer = null;
            if (this._state !== 'scanning' || !this._pendingResult) return false;
            this._presentResult();
            return false;
        });
    }

    _presentResult() {
        const result = this._pendingResult;
        this._pendingResult = null;
        if (!result) return;

        this._state = result.state;
        this._stopAnimations();
        this._icon.style_class = `system-status-icon ${result.state === 'success' ? 'hiro-ok' : 'hiro-fail'}`;
        const text = result.state === 'success'
            ? `✓  Verified${result.score ? ' (' + (result.score * 100).toFixed(0) + '%)' : ''}`
            : (result.reason && result.reason !== 'no_face' ? `Not recognized: ${result.reason}` : 'Not recognized');
        const iconName = result.state === 'success' ? 'object-select-symbolic' : 'dialog-error-symbolic';
        const extraClass = result.state === 'success' ? 'hiro-ok' : 'hiro-fail';
        this._transitionToResult(text, iconName, extraClass);
        this._hideSoon();
    }

    _hideSoon() {
        this._cancelHideTimer();
        this._hideTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, RESULT_MS, () => {
            this._hideTimer = null;
            if (this._state !== 'success' && this._state !== 'failure') return false;
            this._animateOverlayOut(() => {
                this._icon.style_class = 'system-status-icon';
            });
            return false;
        });
    }

    _showOverlay(text, iconName, extraClass, animate = false) {
        this._label.text = text;
        this._boxIcon.icon_name = iconName;
        this._overlay.style_class = 'hiro-status-overlay ' + (extraClass || '');
        this._overlay.visible = true;
        this._positionOverlay();
        if (animate) this._popIn();
    }

    _positionOverlay() {
        // uiGroup's layout does not center children, so place it explicitly
        // relative to the primary monitor.
        const [, natW] = this._overlay.get_preferred_width(-1);
        const [, natH] = this._overlay.get_preferred_height(-1);
        const mon = Main.layoutManager.primaryMonitor;
        const x = Math.round(mon.x + (mon.width - natW) / 2);
        const y = Math.round(mon.y + 24);
        this._overlay.set_position(x, y);
    }

    _transitionToResult(text, iconName, extraClass) {
        const token = ++this._animationToken;
        this._overlay.remove_all_transitions();
        if (!this._overlay.visible) {
            this._showOverlay(text, iconName, extraClass, false);
            this._popIn(token);
            return;
        }

        this._overlay.ease_property('opacity', 0, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._showOverlay(text, iconName, extraClass, false);
                this._overlay.opacity = 0;
                this._overlay.set_scale(0.94, 0.94);
                this._popIn(token);
            },
        });
        this._overlay.ease_property('scale-x', 0.96, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
        this._overlay.ease_property('scale-y', 0.96, {
            duration: TRANSITION_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
    }

    _popIn(token = ++this._animationToken) {
        this._overlay.remove_all_transitions();
        this._overlay.opacity = 0;
        this._overlay.set_scale(0.94, 0.94);
        this._overlay.ease_property('opacity', 255, {
            duration: POP_IN_MS,
            mode: Clutter.AnimationMode.EASE_OUT_QUAD,
        });
        this._overlay.ease_property('scale-x', 1.03, {
            duration: POP_IN_MS,
            mode: Clutter.AnimationMode.EASE_OUT_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._overlay.ease_property('scale-x', 1, {
                    duration: POP_SETTLE_MS,
                    mode: Clutter.AnimationMode.EASE_IN_OUT_QUAD,
                });
                this._overlay.ease_property('scale-y', 1, {
                    duration: POP_SETTLE_MS,
                    mode: Clutter.AnimationMode.EASE_IN_OUT_QUAD,
                });
            },
        });
        this._overlay.ease_property('scale-y', 1.03, {
            duration: POP_IN_MS,
            mode: Clutter.AnimationMode.EASE_OUT_QUAD,
        });
    }

    _animateOverlayOut(onComplete = null) {
        if (!this._overlay || !this._overlay.visible) {
            if (onComplete) onComplete();
            return;
        }
        const token = ++this._animationToken;
        this._overlay.remove_all_transitions();
        this._overlay.ease_property('opacity', 0, {
            duration: HIDE_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
            onComplete: () => {
                if (token !== this._animationToken) return;
                this._overlay.hide();
                this._overlay.opacity = 255;
                this._overlay.set_scale(1, 1);
                if (onComplete) onComplete();
            },
        });
        this._overlay.ease_property('scale-x', 0.96, {
            duration: HIDE_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
        this._overlay.ease_property('scale-y', 0.96, {
            duration: HIDE_MS,
            mode: Clutter.AnimationMode.EASE_IN_QUAD,
        });
    }

    _cancelOverlayAnimation() {
        this._animationToken++;
        if (this._overlay) this._overlay.remove_all_transitions();
    }

    _startPulse() {
        this._stopPulse();
        const token = ++this._pulseToken;
        const pulse = () => {
            if (token !== this._pulseToken || this._state !== 'scanning' || !this._enabled) return;
            this._icon.ease_property('opacity', 90, {
                duration: 450,
                mode: Clutter.AnimationMode.EASE_OUT_QUAD,
                onComplete: () => {
                    if (token !== this._pulseToken || this._state !== 'scanning' || !this._enabled) return;
                    this._icon.ease_property('opacity', 255, {
                        duration: 450,
                        mode: Clutter.AnimationMode.EASE_IN_QUAD,
                        onComplete: () => {
                            if (token === this._pulseToken) pulse();
                        },
                    });
                },
            });
        };
        this._pulse = pulse;
        pulse();
    }

    _startDots() {
        this._stopDots();
        this._dots = 0;
        this._dotTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 500, () => {
            this._dots = (this._dots + 1) % 4;
            if (this._state !== 'scanning') {
                this._dotTimer = null;
                return false;
            }
            this._label.text = 'Scanning your face' + '.'.repeat(this._dots);
            return true;
        });
    }

    _stopAnimations() {
        this._stopPulse();
        this._stopDots();
    }

    _stopPulse() {
        this._pulseToken++;
        this._pulse = null;
        if (!this._icon) return;
        this._icon.remove_all_transitions();
        if (this._enabled) {
            this._icon.ease_property('opacity', 255, {
                duration: TRANSITION_MS,
                mode: Clutter.AnimationMode.EASE_OUT_QUAD,
            });
        } else {
            this._icon.opacity = 255;
        }
    }

    _stopDots() {
        if (this._dotTimer) {
            GLib.source_remove(this._dotTimer);
            this._dotTimer = null;
        }
    }

    _cancelResultTimer() {
        if (this._resultTimer) {
            GLib.source_remove(this._resultTimer);
            this._resultTimer = null;
        }
    }

    _cancelHideTimer() {
        if (this._hideTimer) {
            GLib.source_remove(this._hideTimer);
            this._hideTimer = null;
        }
    }
}
