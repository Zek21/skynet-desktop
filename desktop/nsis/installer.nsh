# Skynet Desktop -- NSIS install-time additions.
#
# Deliberately minimal. Until 2026-08-07 this project shipped with NO custom NSIS script at
# all, which was a genuine review advantage: the wrapper's install-time behaviour was entirely
# stock electron-builder, generated from a declarative config. Every line added here widens
# what a reviewer must read, so this file stays small, does one thing, and explains why.
#
# NOTE ON LOCATION: this lives in desktop/nsis/, NOT desktop/build/. The electron-builder
# `files` glob packages `build/**/*` into app.asar (that is why build/icon.ico is an asar
# member), so a .nsh placed there would become an unexpected asar member and the release gate
# would fail the payload on an exact member-set check.
#
# WHY: the per-user uninstall entry was created with InstallLocation EMPTY. Windows "Apps &
# features" still uninstalls correctly via UninstallString, but enterprise management and
# inventory tooling (Intune, SCCM, asset scanners) read InstallLocation to find the installed
# binaries, and an over-tightened containment check here once rejected the real NSIS
# uninstaller precisely because that field was blank. CDP advisor (Gemini 3.6 Thinking,
# 2026-08-07) reviewed this as incorrect hygiene and prescribed exactly this macro.
#
# SHELL_CONTEXT (not a hardcoded HKCU) so the value lands in the same hive electron-builder
# used for the rest of the uninstall entry, in both per-user and per-machine modes.
# ${UNINSTALL_REGISTRY_KEY} is electron-builder's own define -- see
# app-builder-lib/templates/nsis/include/installer.nsh, which writes DisplayName,
# UninstallString and DisplayVersion to that same key. customInstall runs late in the install
# section, after that entry exists, so this adds a value rather than racing its creation.

!macro customInstall
  WriteRegStr SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}" "InstallLocation" "$INSTDIR"
!macroend
