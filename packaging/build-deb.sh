#!/usr/bin/env bash
# Build a .deb from a release build. Uses dpkg-deb directly (no debhelper
# needed); the packaging/debian tree is for source-package workflows.
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
OUT="packaging/hiro_${VERSION}_amd64.deb"

# TPM2 sealing is optional: build it only when the tss2 dev libraries are
# present, and fall back to the software key manager otherwise.
tpm_features() {
    if pkg-config --exists 'tss2-esys >= 2.4.6' 2>/dev/null; then
        echo "hiro-tpm/tpm"
    else
        echo "warning: libtss2-dev not found - building WITHOUT TPM2 key sealing" >&2
        echo "warning: install libtss2-dev and rebuild for TPM-backed keys" >&2
        echo ""
    fi
}

cargo build --release --features "hiro-face/onnx,$(tpm_features)"

MULTIARCH=${MULTIARCH:-$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
D="$TMP/hiro_${VERSION}_amd64"

install -Dm755 target/release/hirod            "$D/usr/sbin/hirod"
install -Dm755 target/release/hiro             "$D/usr/bin/hiro"
install -Dm755 target/release/hiro-ui          "$D/usr/bin/hiro-ui"
install -Dm755 target/release/libpam_hiro.so   "$D/lib/$MULTIARCH/security/pam_hiro.so"
install -Dm644 etc/hiro/config.toml.example    "$D/etc/hiro/config.toml.example"
install -Dm644 crates/hiro-hw/quirks.toml      "$D/etc/hiro/quirks.toml"
install -Dm644 packaging/systemd/hirod.service         "$D/lib/systemd/system/hirod.service"
install -Dm644 packaging/systemd/hirod-resume.service  "$D/lib/systemd/system/hirod-resume.service"
install -Dm644 packaging/systemd-user/hiro-ui.service  "$D/usr/lib/systemd/user/hiro-ui.service"
install -Dm644 packaging/xdg-autostart/hiro-ui.desktop "$D/etc/xdg/autostart/hiro-ui.desktop"
install -Dm644 packaging/udev/99-hiro.rules            "$D/usr/lib/udev/rules.d/99-hiro.rules"
install -Dm644 packaging/pam-configs/hiro              "$D/usr/share/pam-configs/hiro"
install -Dm644 packaging/polkit/hiro.conf              "$D/usr/share/hiro/polkit-agent-helper-hiro.conf"
install -Dm644 packaging/gnome-shell-extension/hiro-status@hiro/metadata.json    "$D/usr/share/gnome-shell/extensions/hiro-status@hiro/metadata.json"
install -Dm644 packaging/gnome-shell-extension/hiro-status@hiro/extension.js     "$D/usr/share/gnome-shell/extensions/hiro-status@hiro/extension.js"
install -Dm644 packaging/gnome-shell-extension/hiro-status@hiro/stylesheet.css   "$D/usr/share/gnome-shell/extensions/hiro-status@hiro/stylesheet.css"
install -Dm755 scripts/fetch-models.sh                 "$D/usr/share/hiro/fetch-models.sh"
install -Dm644 crates/hiro-face/models/manifest.toml   "$D/usr/share/hiro/models/manifest.toml"
install -Dm644 man/hiro.1       "$D/usr/share/man/man1/hiro.1"
install -Dm644 man/hiro-ui.1    "$D/usr/share/man/man1/hiro-ui.1"
install -Dm644 man/hirod.8      "$D/usr/share/man/man8/hirod.8"
install -Dm644 man/pam_hiro.8   "$D/usr/share/man/man8/pam_hiro.8"
install -Dm644 man/hiro.conf.5  "$D/usr/share/man/man5/hiro.conf.5"
install -Dm644 README.md          "$D/usr/share/doc/hiro/README.md"
install -Dm644 docs/security.md   "$D/usr/share/doc/hiro/security.md"
install -Dm644 docs/hardware.md   "$D/usr/share/doc/hiro/hardware.md"
install -Dm644 docs/pam.md        "$D/usr/share/doc/hiro/pam.md"

mkdir -p "$D/DEBIAN"
cat > "$D/DEBIAN/control" <<EOF
Package: hiro
Version: $VERSION
Section: admin
Priority: optional
Architecture: amd64
Maintainer: HIRO Developers <hiro@example.org>
Installed-Size: $(du -sk "$D" | cut -f1)
Depends: libpam-runtime, libgtk-3-0
Recommends: linux-enable-ir-emitter, v4l-utils
Description: Windows Hello-style face authentication for Linux
 HIRO uses your laptop's built-in Windows Hello IR camera to authenticate
 through PAM: login, lock screen, sudo, and polkit prompts. Face templates
 are stored as encrypted embeddings, never images, and the IR emitter is
 driven automatically. Everything runs locally - no network, no cloud.
 hiro-ui provides a desktop-agnostic scan indicator and approval prompt.
EOF

cp packaging/debian/postinst "$D/DEBIAN/postinst"
cp packaging/debian/prerm    "$D/DEBIAN/prerm"
chmod 755 "$D/DEBIAN/postinst" "$D/DEBIAN/prerm"

dpkg-deb --build "$D" "$OUT"
echo "built $OUT"
