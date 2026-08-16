%global __cargo_common_opts %{nil}

Name:           hiro
Version:        0.1.0
Release:        1%{?dist}
Summary:        Windows Hello-style face authentication for Linux

License:        MIT
URL:            https://github.com/hiro-auth/hiro
Source0:        https://github.com/hiro-auth/hiro/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  tss2-devel
Requires:       pam
Recommends:     v4l-utils
Suggests:       linux-enable-ir-emitter

%description
HIRO uses your laptop's built-in Windows Hello IR camera to authenticate
through PAM: login, lock screen, sudo, and polkit prompts. Face templates
are stored as encrypted embeddings, never images. Everything runs locally.

%prep
%autosetup -n hiro-%{version}

%build
cargo build --release --features hiro-face/onnx,hiro-tpm/tpm

%install
install -Dm755 target/release/hirod %{buildroot}%{_sbindir}/hirod
install -Dm755 target/release/hiro %{buildroot}%{_bindir}/hiro
install -Dm755 target/release/libpam_hiro.so %{buildroot}%{_libdir}/security/pam_hiro.so

install -Dm644 etc/hiro/config.toml.example %{buildroot}%{_sysconfdir}/hiro/config.toml.example
install -Dm644 crates/hiro-hw/quirks.toml %{buildroot}%{_sysconfdir}/hiro/quirks.toml

install -Dm644 packaging/systemd/hirod.service %{buildroot}%{_unitdir}/hirod.service
install -Dm644 packaging/systemd/hirod-resume.service %{buildroot}%{_unitdir}/hirod-resume.service
install -Dm644 packaging/udev/99-hiro.rules %{buildroot}%{_udevrulesdir}/99-hiro.rules
install -Dm644 packaging/polkit/hiro.conf %{buildroot}%{_datadir}/hiro/polkit-agent-helper-hiro.conf
install -Dm644 packaging/gnome-shell-extension/hiro-status@hiro/metadata.json %{buildroot}%{_datadir}/gnome-shell/extensions/hiro-status@hiro/metadata.json
install -Dm644 packaging/gnome-shell-extension/hiro-status@hiro/extension.js %{buildroot}%{_datadir}/gnome-shell/extensions/hiro-status@hiro/extension.js
install -Dm644 packaging/gnome-shell-extension/hiro-status@hiro/stylesheet.css %{buildroot}%{_datadir}/gnome-shell/extensions/hiro-status@hiro/stylesheet.css

install -Dm755 scripts/fetch-models.sh %{buildroot}%{_datadir}/hiro/fetch-models.sh
install -Dm644 crates/hiro-face/models/manifest.toml %{buildroot}%{_datadir}/hiro/models/manifest.toml

install -Dm644 man/hiro.1 %{buildroot}%{_mandir}/man1/hiro.1
install -Dm644 man/hirod.8 %{buildroot}%{_mandir}/man8/hirod.8
install -Dm644 man/pam_hiro.8 %{buildroot}%{_mandir}/man8/pam_hiro.8
install -Dm644 man/hiro.conf.5 %{buildroot}%{_mandir}/man5/hiro.conf.5

%post
%systemd_post hirod.service hirod-resume.service
# Fedora uses authselect; PAM integration is a manual step (see docs/pam.md):
#   authselect enable-feature with-hiro   (once a feature is shipped upstream)

%preun
%systemd_preun hirod.service hirod-resume.service

%postun
%systemd_postun hirod.service hirod-resume.service

%files
%license LICENSE
%doc README.md docs/security.md docs/hardware.md docs/pam.md
%{_sbindir}/hirod
%{_bindir}/hiro
%{_libdir}/security/pam_hiro.so
%dir %{_sysconfdir}/hiro
%config(noreplace) %{_sysconfdir}/hiro/config.toml.example
%config(noreplace) %{_sysconfdir}/hiro/quirks.toml
%{_unitdir}/hirod.service
%{_unitdir}/hirod-resume.service
%{_udevrulesdir}/99-hiro.rules
%{_datadir}/hiro/
%{_mandir}/man1/hiro.1*
%{_mandir}/man8/hirod.8*
%{_mandir}/man8/pam_hiro.8*
%{_mandir}/man5/hiro.conf.5*

%changelog
* Sun Aug 16 2026 HIRO Developers <hiro@example.org> - 0.1.0-1
- Initial package
