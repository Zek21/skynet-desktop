"""A PAPERWORK failure must never suppress the empirical install/launch/uninstall audit.

Observed LIVE 2026-08-07 on "Skynet Desktop Setup 0.1.1-unsigned.exe": the allowlist still
bound the PREVIOUS build's sha256, so `installer_wrapper_not_dual_approved` landed in
`errors`, and the audit site -- then guarded by a bare `if not errors:` -- skipped the real
silent NSIS install, the UI launch and the uninstall-residue verification entirely. The
report surfaced that as `nsis_install_audit: {}` / `ui_launch_audit: {}`, which reads as
"checked, nothing to say" rather than "never ran". Net effect: the strongest evidence the
gate can produce was withheld precisely because an administrative hash re-bind was pending.

CDP advisor (Gemini 3.6 Thinking, 2026-08-07) reviewed the control flow and called it "a
severe gating logic defect", prescribing accumulate-all-errors: run static checks, run the
empirical audit REGARDLESS, then fail if any error landed. It accepted exactly one reason to
skip -- executing an artifact whose integrity is already disproven -- which is
`gate.EMPIRICAL_AUDIT_BLOCKERS`.

These tests pin both halves so the short-circuit cannot come back.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# The fixture harness (installer/asar/source builders) lives in the sibling gate test module;
# reuse it rather than duplicating a second, drifting copy of the same fixtures. APPEND it --
# inserting at 0 puts tests/ ahead of the repo root, and tests/tools/__init__.py then shadows
# the real `tools` package, so `from tools import skynet_desktop_release_gate` fails.
_TESTS_DIR = str(Path(__file__).resolve().parent)
if _TESTS_DIR not in sys.path:
    sys.path.append(_TESTS_DIR)

from tools import skynet_desktop_release_gate as gate  # noqa: E402

from test_skynet_desktop_release_gate import evaluate  # noqa: E402


def _unapproved_allowlist():
    """An allowlist bound to some OTHER build's hash -- the exact live 0.1.1 condition."""
    return (
        {
            "schema": "skynet_desktop_installer_allowlist/1",
            "productName": "Skynet Desktop",
            "version": "0.1.1",
            "distributionMode": "unsigned",
            "installerName": "Skynet Desktop Setup 0.1.1-unsigned.exe",
            "installerSha256": "b1" * 32,
        },
        "D" * 64,
    )


def test_an_unapproved_wrapper_hash_still_fails_the_gate(tmp_path: Path):
    """The paperwork check itself must keep its teeth."""
    result = evaluate(tmp_path, installer_allowlist_record=_unapproved_allowlist())

    assert result["ok"] is False
    assert "installer_wrapper_not_dual_approved" in result["errors"]


def test_an_unapproved_wrapper_hash_does_NOT_skip_the_empirical_audit(tmp_path: Path):
    """The regression: the install/launch audit must still RUN and report real findings."""
    result = evaluate(tmp_path, installer_allowlist_record=_unapproved_allowlist())

    assert result["nsis_install_audit"], "empirical install audit was suppressed by paperwork"
    assert result["ui_launch_audit"], "UI launch audit was suppressed by paperwork"
    assert result["nsis_install_audit"].get("ran") is not False
    assert result["ui_launch_audit"].get("ok") is True
    assert result["nsis_install_audit"]["installer_returncode"] == 0


def test_empirical_failures_are_still_caught_when_paperwork_also_failed(tmp_path: Path):
    """Both error classes must accumulate -- neither one masks the other."""
    result = evaluate(
        tmp_path,
        installer_allowlist_record=_unapproved_allowlist(),
        ui_auditor=lambda _path, _policy: {"ok": False, "error": "no page target"},
    )

    assert "installer_wrapper_not_dual_approved" in result["errors"]
    assert "installed_electron_ui_launch_audit_failed" in result["errors"], (
        "a real UI launch failure went unreported because paperwork failed first"
    )


def test_a_structural_failure_DOES_skip_the_audit_and_says_why(tmp_path: Path):
    """The one legitimate skip: never execute an artifact whose integrity is disproven."""

    def broken_extraction(_installer, _policy):
        raise RuntimeError("payload could not be extracted")

    result = evaluate(tmp_path, extraction_context=broken_extraction)

    assert "installer_payload_verification_failed" in result["errors"]
    assert result["nsis_install_audit"]["ran"] is False
    assert "installer_payload_verification_failed" in result["nsis_install_audit"]["blocked_by"]
    assert result["ui_launch_audit"]["ran"] is False


def test_the_blocker_set_is_structural_only_and_excludes_paperwork():
    """Guard the classification itself: no administrative error may join the skip set."""
    assert "installer_wrapper_not_dual_approved" not in gate.EMPIRICAL_AUDIT_BLOCKERS
    assert "installer_payload_verification_failed" in gate.EMPIRICAL_AUDIT_BLOCKERS
    assert "electron_identity_verification_failed" in gate.EMPIRICAL_AUDIT_BLOCKERS


def test_a_clean_release_still_passes_end_to_end(tmp_path: Path):
    """The change must not make a good build fail."""
    result = evaluate(tmp_path)

    assert result["ok"] is True, result["errors"]
    assert result["nsis_install_audit"]["installer_returncode"] == 0
