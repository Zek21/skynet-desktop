"""Release approval binds REVIEWABLE SOURCE, not the 99.7MB wrapper blob.

Why schema /2 exists: the /1 allowlist binds the NSIS wrapper's sha256, so approving a rebuild
means a reviewer must inspect a 99.7MB binary. That is impossible through any review channel --
six approval rounds deadlocked on exactly this, and the blocker was a CHANNEL limit, not an
evidence-quality problem. CDP advisor (Gemini 3.6 Thinking, 2026-08-07) ranked it a BLOCKER and
prescribed moving approval upstream to reviewable source plus automated attestation.

/2 binds two digests instead:
  * sourceDigest        -- the 10 reviewed payload files (~300KB of readable text/assets)
  * wrapperConfigDigest -- the declarative build config + every declared nsis include

The wrapper itself is then derived mechanically, and the REST of the gate already proves the
link: verify_asar_identity pins the asar member set and hashes to these same files,
payload_binding proves the installer-embedded asar/application match the built ones, and
verify_complete_payload_tree proves the extracted tree matches file-for-file.

These tests pin that /2 is strictly fail-closed -- it must reject every substitution /1 would.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_TESTS_DIR = str(Path(__file__).resolve().parent)
if _TESTS_DIR not in sys.path:
    sys.path.append(_TESTS_DIR)

from tools import skynet_desktop_build_stamp as stamp  # noqa: E402
from tools import skynet_desktop_release_gate as gate  # noqa: E402

from test_skynet_desktop_release_gate import package as fixture_package  # noqa: E402


COMMITTED_RECEIPT = {"order_id": "rule1_test", "intent_sha256": "E" * 64, "state": "COMMITTED"}


@pytest.fixture
def source_tree(tmp_path):
    """A payload plus the declared nsis include, mirroring the real desktop/ layout."""
    for member in stamp.SOURCE_MEMBERS:
        path = tmp_path / Path(member)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"contents of {member}".encode("utf-8"))
    include = tmp_path / "nsis" / "installer.nsh"
    include.parent.mkdir(parents=True, exist_ok=True)
    include.write_text("!macro customInstall\n!macroend\n", encoding="utf-8")
    return tmp_path


def _allowlist(package, source_root, **overrides):
    source_digest, _ = stamp.compute_source_digest(source_root)
    wrapper_digest, _ = stamp.compute_wrapper_config_digest(package, source_root)
    record = {
        "schema": "skynet_desktop_installer_allowlist/2",
        "productName": "Skynet Desktop",
        "version": package["version"],
        "distributionMode": package["skynetRelease"]["distributionMode"],
        "installerName": stamp.installer_name(
            package["version"], package["skynetRelease"]["distributionMode"]
        ),
        "sourceDigest": source_digest,
        "wrapperConfigDigest": wrapper_digest,
    }
    record.update(overrides)
    return record


def _installer_for(source_root, tmp_path):
    """The public artifact, named exactly as the build driver names it."""
    path = tmp_path / stamp.installer_name("0.1.1", "unsigned")
    path.write_bytes(b"wrapper bytes nobody can review by hand")
    return path


def _verify(source_root, tmp_path, allowlist=None, installer=None, package=None):
    package = package or fixture_package()
    return gate.verify_installer_allowlist(
        installer if installer is not None else _installer_for(source_root, tmp_path),
        package,
        allowlist if allowlist is not None else _allowlist(package, source_root),
        "D" * 64,
        receipt_finder=lambda _sha: COMMITTED_RECEIPT,
        source_root=source_root,
    )


def test_approved_source_approves_the_wrapper_without_reviewing_its_bytes(source_tree, tmp_path):
    result = _verify(source_tree, tmp_path)

    assert result["ok"] is True, result["errors"]
    assert result["binding"] == "source_digest"


def test_a_changed_payload_is_rejected(source_tree, tmp_path):
    """One byte of shipped code changing must invalidate the approval."""
    allowlist = _allowlist(fixture_package(), source_tree)
    (source_tree / "renderer" / "app.js").write_bytes(b"attacker supplied renderer")

    result = _verify(source_tree, tmp_path, allowlist=allowlist)

    assert result["ok"] is False
    assert "installer_source_digest_not_approved" in result["errors"]


def test_a_changed_install_time_script_is_rejected(source_tree, tmp_path):
    """The gap /1 reviewers correctly worried about: NSIS actions outside the asar."""
    allowlist = _allowlist(fixture_package(), source_tree)
    (source_tree / "nsis" / "installer.nsh").write_text(
        "!macro customInstall\n  ExecShell open \"payload.exe\"\n!macroend\n", encoding="utf-8"
    )

    result = _verify(source_tree, tmp_path, allowlist=allowlist)

    assert result["ok"] is False
    assert "installer_wrapper_config_not_approved" in result["errors"]


def test_a_changed_build_config_is_rejected(source_tree, tmp_path):
    """Flipping perMachine or adding extraResources changes what gets installed."""
    package = fixture_package()
    allowlist = _allowlist(package, source_tree)
    package["build"]["nsis"]["perMachine"] = True

    result = _verify(source_tree, tmp_path, allowlist=allowlist, package=package)

    assert result["ok"] is False
    assert "installer_wrapper_config_not_approved" in result["errors"]


def test_an_installer_under_a_different_name_is_rejected(source_tree, tmp_path):
    """The file on disk must be the file that was approved."""
    other = tmp_path / "Skynet-Desktop-Setup-0.9.9-x64.exe"
    other.write_bytes(b"a different build entirely")

    result = _verify(source_tree, tmp_path, installer=other)

    assert result["ok"] is False
    assert "installer_name_not_approved" in result["errors"]


def test_the_approved_name_is_the_professional_public_name(source_tree, tmp_path):
    """Approval must not re-introduce build plumbing into the end-user filename."""
    allowlist = _allowlist(fixture_package(), source_tree)

    assert allowlist["installerName"] == "Skynet-Desktop-Setup-0.1.1-x64.exe"


def test_a_missing_approval_receipt_fails_closed(source_tree, tmp_path):
    def no_receipt(_sha):
        raise RuntimeError("no committed Rule 1 order for this allowlist")

    result = gate.verify_installer_allowlist(
        _installer_for(source_tree, tmp_path),
        fixture_package(),
        _allowlist(fixture_package(), source_tree),
        "D" * 64,
        receipt_finder=no_receipt,
        source_root=source_tree,
    )

    assert result["ok"] is False
    assert any(e.startswith("installer_allowlist_receipt_invalid") for e in result["errors"])


def test_extra_or_missing_allowlist_fields_are_rejected(source_tree, tmp_path):
    """An allowlist must not smuggle in unreviewed keys."""
    allowlist = _allowlist(fixture_package(), source_tree, note="please approve")

    result = _verify(source_tree, tmp_path, allowlist=allowlist)

    assert result["ok"] is False
    assert "installer_allowlist_fields_not_exact" in result["errors"]


def test_a_non_hex_digest_is_rejected(source_tree, tmp_path):
    allowlist = _allowlist(fixture_package(), source_tree, sourceDigest="not-a-digest")

    result = _verify(source_tree, tmp_path, allowlist=allowlist)

    assert result["ok"] is False
    assert "installer_allowlist_digest_invalid" in result["errors"]


def test_an_unknown_schema_never_falls_back_to_the_weaker_check(source_tree, tmp_path):
    """An unrecognised schema must be rejected, not silently treated as /1."""
    allowlist = _allowlist(fixture_package(), source_tree)
    allowlist["schema"] = "skynet_desktop_installer_allowlist/99"

    result = _verify(source_tree, tmp_path, allowlist=allowlist)

    assert result["ok"] is False


def test_schema_1_blob_binding_still_works(tmp_path):
    """/2 is additive: the existing hash-bound path must keep functioning unchanged."""
    package = fixture_package()
    installer = tmp_path / stamp.installer_name(package["version"], "unsigned")
    installer.write_bytes(b"wrapper")
    allowlist = {
        "schema": "skynet_desktop_installer_allowlist/1",
        "productName": "Skynet Desktop",
        "version": package["version"],
        "distributionMode": "unsigned",
        "installerName": installer.name,
        "installerSha256": gate._sha256(installer),
    }

    result = gate.verify_installer_allowlist(
        installer, package, allowlist, "D" * 64, receipt_finder=lambda _s: COMMITTED_RECEIPT
    )

    assert result["ok"] is True, result["errors"]
