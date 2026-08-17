#!/usr/bin/env bash
#
# redeploy.sh — build HIRO from this checkout and (re)install everything a
# packaged install would place on the system, then restart the daemon.
#
# Usage:
#   sudo ./scripts/redeploy.sh              # full build + deploy
#   sudo ./scripts/redeploy.sh --skip-build # reuse existing target/release
#
# Installs to the same paths as the .deb produced by packaging/build-deb.sh:
#   /usr/sbin/hirod   /usr/bin/hiro   pam_hiro.so
#   /usr/lib/hiro/hiro-approve  (secure-desktop approval dialog)
#   /etc/hiro/config.toml(.example)   /etc/hiro/quirks.toml
#   systemd units + udev rule + pam-config profile + polkit drop-in
#   GNOME Shell extension  /usr/share/gnome-shell/extensions/hiro-status@hiro
#   man pages, docs, model manifest, fetch-models script
#
# Your data and config are preserved:
#   - /var/lib/hiro (keys, templates, keyring secret) — never touched
#   - /etc/hiro/config.toml — only written if it does not already exist
#
# The build runs as the user who invoked sudo, so target/ stays owned by
# you (a root-owned target/ breaks later `cargo` runs).
#
set -euo pipefail

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    echo
    echo "Options:"
    echo "  --skip-build   skip cargo build; install existing target/release binaries"
    echo "  -h, --help     show this help"
}

SKIP_BUILD=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $arg" >&2; usage >&2; exit 1 ;;
    esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(grep -m1 '^version' "$REPO/Cargo.toml" | cut -d'"' -f2)"

if [[ $(id -u) -ne 0 ]]; then
    echo "error: run with sudo:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

BUILD_USER="${SUDO_USER:-root}"
if [[ "$BUILD_USER" != "root" ]] && ! id "$BUILD_USER" >/dev/null 2>&1; then
    echo "warning: SUDO_USER '$BUILD_USER' is not a real user; building as root" >&2
    BUILD_USER=root
fi

echo "== HIRO redeploy v$VERSION (repo: $REPO) =="
echo "   build user : $BUILD_USER"
echo "   skip build : $([ "$SKIP_BUILD" = 1 ] && echo yes || echo no)"

# --- build ------------------------------------------------------------------
# sudo (especially with `secure_path`) strips ~/.cargo/bin from PATH, so
# locate the real cargo binary instead of relying on PATH inside the
# subprocess. Priority: current PATH -> the build user's ~/.cargo/bin ->
# their login shell (which sources ~/.profile / ~/.bashrc).
find_cargo() {
    local user="$1" home found
    if command -v cargo >/dev/null 2>&1; then
        command -v cargo
        return 0
    fi
    home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
    [ -n "$home" ] || home="$(eval echo "~$user")"
    for c in "$home/.cargo/bin/cargo" "$home/.local/bin/cargo"; do
        if [ -x "$c" ]; then
            printf '%s\n' "$c"
            return 0
        fi
    done
    if [ "$user" != "root" ]; then
        found="$(sudo -u "$user" bash -lc 'command -v cargo' 2>/dev/null)" || true
        if [ -n "$found" ]; then
            printf '%s\n' "$found"
            return 0
        fi
    fi
    return 1
}

if [ "$SKIP_BUILD" = 0 ]; then
    TPM_FEATURES=""
    if pkg-config --exists 'tss2-esys >= 2.4.6' 2>/dev/null; then
        TPM_FEATURES="hiro-tpm/tpm"
        echo "== building (release) with TPM2 key sealing =="
    else
        echo "== building (release) WITHOUT TPM2 key sealing (libtss2-dev not found) =="
        echo "   (install libtss2-dev for TPM-backed keys)"
    fi
    FEATURES="hiro-face/onnx${TPM_FEATURES:+,$TPM_FEATURES}"

    CARGO_BIN="$(find_cargo "$BUILD_USER")" || {
        echo "error: cannot locate cargo for user '$BUILD_USER'." >&2
        echo "       Install it with https://rustup.rs (default ~/.cargo/bin) or 'apt install cargo'." >&2
        exit 1
    }
    echo "   cargo     : $CARGO_BIN"

    if [ "$BUILD_USER" != "root" ]; then
        if ! sudo -u "$BUILD_USER" --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME \
            bash -c 'cd "$1" && exec "$2" build --release --features "$3"' \
            _ "$REPO" "$CARGO_BIN" "$FEATURES"; then
            echo "error: build failed (as $BUILD_USER)." >&2
            exit 1
        fi
    else
        ( cd "$REPO" && exec "$CARGO_BIN" build --release --features "$FEATURES" )
    fi
else
    echo "== skipping build (--skip-build); installing existing target/release binaries =="
fi

# --- install ----------------------------------------------------------------
MULTIARCH="${MULTIARCH:-$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)}"
MULTIARCH="${MULTIARCH:-x86_64-linux-gnu}"
if [ -d "/lib/$MULTIARCH/security" ]; then
    PAM_DIR="/lib/$MULTIARCH/security"
elif [ -d "/usr/lib/$MULTIARCH/security" ]; then
    PAM_DIR="/usr/lib/$MULTIARCH/security"
elif [ -d /usr/lib64/security ]; then
    PAM_DIR="/usr/lib64/security"
else
    PAM_DIR="/usr/lib/security"
fi

echo "== installing binaries (PAM module -> $PAM_DIR) =="
install -Dm755 "$REPO/target/release/hirod"          /usr/sbin/hirod
install -Dm755 "$REPO/target/release/hiro"           /usr/bin/hiro
install -Dm755 "$REPO/target/release/libpam_hiro.so" "$PAM_DIR/pam_hiro.so"
# Secure-desktop approval dialog — the daemon spawns this via systemd-run
# when approval.secure_desktop = true. Default approval.secure_dialog
# points here, so keep the path in sync with crates/hiro-core config.rs.
install -Dm755 "$REPO/target/release/hiro-approve"   /usr/lib/hiro/hiro-approve

echo "== installing configuration =="
mkdir -p /etc/hiro
install -m644 "$REPO/etc/hiro/config.toml.example" /etc/hiro/config.toml.example
if [ ! -e /etc/hiro/config.toml ]; then
    install -m644 "$REPO/etc/hiro/config.toml.example" /etc/hiro/config.toml
    echo "   wrote /etc/hiro/config.toml (from example)"
else
    echo "   keeping existing /etc/hiro/config.toml"
fi
install -m644 "$REPO/crates/hiro-hw/quirks.toml" /etc/hiro/quirks.toml

echo "== installing systemd units, udev rule, PAM profile, polkit drop-in =="
install -Dm644 "$REPO/packaging/systemd/hirod.service"        /lib/systemd/system/hirod.service
install -Dm644 "$REPO/packaging/systemd/hirod-resume.service" /lib/systemd/system/hirod-resume.service
install -Dm644 "$REPO/packaging/udev/99-hiro.rules"           /usr/lib/udev/rules.d/99-hiro.rules
install -Dm644 "$REPO/packaging/pam-configs/hiro"             /usr/share/pam-configs/hiro
install -Dm644 "$REPO/packaging/polkit/hiro.conf"             /usr/share/hiro/polkit-agent-helper-hiro.conf
mkdir -p /etc/systemd/system/polkit-agent-helper@.service.d
cp -n /usr/share/hiro/polkit-agent-helper-hiro.conf \
      /etc/systemd/system/polkit-agent-helper@.service.d/hiro.conf || true
if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules 2>/dev/null || true
fi

echo "== installing GNOME Shell extension =="
EXT_DIR="/usr/share/gnome-shell/extensions/hiro-status@hiro"
install -Dm644 "$REPO/packaging/gnome-shell-extension/hiro-status@hiro/metadata.json"   "$EXT_DIR/metadata.json"
install -Dm644 "$REPO/packaging/gnome-shell-extension/hiro-status@hiro/extension.js"    "$EXT_DIR/extension.js"
install -Dm644 "$REPO/packaging/gnome-shell-extension/hiro-status@hiro/stylesheet.css"  "$EXT_DIR/stylesheet.css"

# A user-local extension copy (per the README alternative install) would
# shadow the system-wide one — refresh it too.
if [ "$BUILD_USER" != "root" ]; then
    LOCAL_EXT="$(sudo -u "$BUILD_USER" sh -c 'printf %s "$HOME"')/.local/share/gnome-shell/extensions/hiro-status@hiro"
    if [ -d "$LOCAL_EXT" ]; then
        echo "== refreshing user-local extension copy ($LOCAL_EXT) =="
        install -m644 "$REPO/packaging/gnome-shell-extension/hiro-status@hiro/metadata.json"   "$LOCAL_EXT/metadata.json"
        install -m644 "$REPO/packaging/gnome-shell-extension/hiro-status@hiro/extension.js"    "$LOCAL_EXT/extension.js"
        install -m644 "$REPO/packaging/gnome-shell-extension/hiro-status@hiro/stylesheet.css"  "$LOCAL_EXT/stylesheet.css"
    fi
fi

echo "== installing man pages, docs, model manifest, fetch script =="
install -Dm644 "$REPO/man/hiro.1"       /usr/share/man/man1/hiro.1
install -Dm644 "$REPO/man/hirod.8"      /usr/share/man/man8/hirod.8
install -Dm644 "$REPO/man/pam_hiro.8"   /usr/share/man/man8/pam_hiro.8
install -Dm644 "$REPO/man/hiro.conf.5"  /usr/share/man/man5/hiro.conf.5
install -Dm644 "$REPO/README.md"        /usr/share/doc/hiro/README.md
install -Dm644 "$REPO/docs/security.md" /usr/share/doc/hiro/security.md
install -Dm644 "$REPO/docs/hardware.md" /usr/share/doc/hiro/hardware.md
install -Dm644 "$REPO/docs/pam.md"      /usr/share/doc/hiro/pam.md
install -Dm755 "$REPO/scripts/fetch-models.sh"               /usr/share/hiro/fetch-models.sh
install -Dm644 "$REPO/crates/hiro-face/models/manifest.toml" /usr/share/hiro/models/manifest.toml

# --- one-time data initialization ------------------------------------------
if ! getent group hiro >/dev/null 2>&1; then
    echo "== creating the 'hiro' group (camera access for hiro doctor) =="
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system hiro
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup --system hiro
    fi
fi
if [ ! -e /var/lib/hiro/hiro.key ]; then
    echo "== initializing keys and database (hirod --init-keys) =="
    mkdir -p /var/lib/hiro
    chmod 700 /var/lib/hiro
    /usr/sbin/hirod --init-keys
fi
mkdir -p /var/lib/hiro
chmod 700 /var/lib/hiro

# --- PAM profile (Debian/Ubuntu) -------------------------------------------
if command -v pam-auth-update >/dev/null 2>&1; then
    echo "== refreshing pam-auth-update profile =="
    DEBIAN_FRONTEND=noninteractive pam-auth-update --package
fi

# --- services ---------------------------------------------------------------
RESTARTED=0
if command -v systemctl >/dev/null 2>&1; then
    echo "== enabling and restarting hirod =="
    systemctl daemon-reload
    systemctl enable hirod.service hirod-resume.service >/dev/null 2>&1 || true
    if systemctl restart hirod; then
        RESTARTED=1
    else
        echo "warning: hirod failed to restart - see 'systemctl status hirod'" >&2
        echo "         (usually missing IR models - see the note below)" >&2
    fi
else
    echo "warning: systemctl not found; start hirod manually (hirod &)" >&2
fi

# --- model check ------------------------------------------------------------
if ! compgen -G '/usr/share/hiro/models/*.onnx' >/dev/null 2>&1; then
    echo
    echo "!! No IR models found in /usr/share/hiro/models"
    echo "   Run:  sudo /usr/share/hiro/fetch-models.sh"
fi

# --- done -------------------------------------------------------------------
echo
echo "== done =="
echo "   hirod : $(/usr/sbin/hirod --version 2>/dev/null || echo installed)"
echo "   hiro  : $(/usr/bin/hiro --version 2>/dev/null || echo installed)"
echo "   hirod : $([ "$RESTARTED" = 1 ] && echo 'restarted' || echo 'NOT running (see warnings)')"
echo
echo "Next steps:"
echo "   sudo hiro doctor          # sanity check (camera, IR, models, daemon)"
echo "   hiro enroll               # if you have not enrolled your face yet"
echo "   hiro test                 # verify recognition + liveness"
echo
echo "The GNOME Shell extension was updated system-wide. To load it in your"
echo "session, restart the shell (Alt+F2, type 'r') or log out/in, then:"
echo "   gnome-extensions enable hiro-status@hiro"
