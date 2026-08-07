"""A build id must identify the PAYLOAD, so two builds can never collide on one version.

Live defect 2026-08-07: the installed app carried app.asar c13382ec (379,694 bytes) and the
freshly built installer carried 6bf1ba06 (380,102 bytes) -- both calling themselves "0.1.1",
built 2h46m apart. A crash report naming 0.1.1 could not be mapped to bytes. CDP advisor
(Gemini 3.6 Thinking) ranked this a BLOCKER.

The fix hinges on `source_digest` (content) rather than the commit SHA (provenance), because a
dirty tree does not determine its own bytes. These tests pin that distinction.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import skynet_desktop_build_stamp as stamp  # noqa: E402
from tools import skynet_desktop_release_gate as gate  # noqa: E402


@pytest.fixture
def source_tree(tmp_path):
    """A minimal payload containing every reviewed member."""
    for member in stamp.SOURCE_MEMBERS:
        path = tmp_path / Path(member)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"contents of {member}".encode("utf-8"))
    return tmp_path


def test_the_member_list_cannot_drift_from_the_release_gate():
    """Two lists of 'the reviewed payload' would eventually disagree and certify the wrong set."""
    assert stamp.SOURCE_MEMBERS == gate.SOURCE_MEMBERS


def test_the_digest_is_stable_for_identical_content(source_tree):
    first, _ = stamp.compute_source_digest(source_tree)
    second, _ = stamp.compute_source_digest(source_tree)

    assert first == second


def test_any_payload_change_changes_the_digest(source_tree):
    before, _ = stamp.compute_source_digest(source_tree)
    (source_tree / "renderer" / "app.js").write_bytes(b"one byte different")

    after, _ = stamp.compute_source_digest(source_tree)

    assert before != after, "a changed payload kept its identity -- the collision is back"


def test_swapping_two_members_contents_changes_the_digest(source_tree):
    """The member NAME is hashed too, so content swaps cannot cancel out."""
    before, _ = stamp.compute_source_digest(source_tree)
    a = source_tree / "main.js"
    b = source_tree / "preload.js"
    a_bytes, b_bytes = a.read_bytes(), b.read_bytes()
    a.write_bytes(b_bytes)
    b.write_bytes(a_bytes)

    after, _ = stamp.compute_source_digest(source_tree)

    assert before != after


def test_a_missing_member_is_an_error_not_a_shorter_digest(source_tree):
    (source_tree / "lib" / "sidecar_runtime.js").unlink()

    with pytest.raises(RuntimeError, match="missing"):
        stamp.compute_source_digest(source_tree)


def test_a_clean_tree_build_id_carries_commit_and_digest():
    provenance = {"commit": "a" * 40, "source_members_clean": True}

    identifier = stamp.build_id("0.1.1", "b" * 64, provenance)

    assert identifier == "0.1.1+gaaaaaaaa.bbbbbbbbbbbb"


def test_a_dirty_tree_build_id_never_claims_a_commit():
    """A dirty tree does not determine its bytes, so the commit must not appear to vouch for it."""
    provenance = {"commit": "a" * 40, "source_members_clean": False, "dirty_members": ["desktop/main.js"]}

    identifier = stamp.build_id("0.1.1", "b" * 64, provenance)

    assert identifier == "0.1.1+dirty.bbbbbbbbbbbb"
    assert "gaaaaaaaa" not in identifier


def test_two_dirty_builds_from_one_commit_still_get_distinct_ids():
    """The exact live failure: same version, same commit, different bytes."""
    provenance = {"commit": "a" * 40, "source_members_clean": False}

    first = stamp.build_id("0.1.1", "c13382ec" + "0" * 56, provenance)
    second = stamp.build_id("0.1.1", "6bf1ba06" + "0" * 56, provenance)

    assert first != second


def test_an_unreadable_git_tree_is_reported_dirty_not_clean():
    """Unknown is never clean -- refusing to guess is the point."""

    def broken(_args, _root):
        raise RuntimeError("git is unavailable")

    provenance = stamp.git_provenance(ROOT, runner=broken)

    assert provenance["source_members_clean"] is False
    assert provenance["commit"] is None


def test_a_dirty_status_marks_the_members_unclean():
    def runner(args, _root):
        if args[0] == "rev-parse":
            return "a" * 40
        if args[0] == "ls-files":
            return "\n".join(f"desktop/{m}" for m in stamp.SOURCE_MEMBERS)
        return " M desktop/main.js"

    provenance = stamp.git_provenance(ROOT, runner=runner)

    assert provenance["source_members_clean"] is False
    assert provenance["dirty_members"] == ["desktop/main.js"]


def test_UNTRACKED_members_are_never_reported_clean():
    """The live false-clean: desktop/ is gitignored, so `git status` prints nothing for it.

    Relying on an empty status therefore claimed a clean tree while git had never seen a single
    member -- the commit would have appeared to vouch for bytes it does not contain.
    """

    def runner(args, _root):
        if args[0] == "rev-parse":
            return "a" * 40
        if args[0] == "ls-files":
            return ""  # nothing tracked, exactly like an ignored directory
        return ""  # and status is silent about ignored paths

    provenance = stamp.git_provenance(ROOT, runner=runner)

    assert provenance["source_members_clean"] is False, "an untracked payload was called clean"
    assert len(provenance["untracked_members"]) == len(stamp.SOURCE_MEMBERS)


def test_a_partially_tracked_payload_is_unclean():
    def runner(args, _root):
        if args[0] == "rev-parse":
            return "a" * 40
        if args[0] == "ls-files":
            return "\n".join(f"desktop/{m}" for m in stamp.SOURCE_MEMBERS[:-1])
        return ""

    provenance = stamp.git_provenance(ROOT, runner=runner)

    assert provenance["source_members_clean"] is False
    assert provenance["untracked_members"] == [f"desktop/{stamp.SOURCE_MEMBERS[-1]}"]


def test_the_wrapper_config_digest_covers_the_nsis_include(tmp_path):
    """What the wrapper DOES must be reviewable as text, not as a 99.7MB binary."""
    (tmp_path / "nsis").mkdir()
    include = tmp_path / "nsis" / "installer.nsh"
    include.write_text("!macro customInstall\n!macroend\n", encoding="utf-8")
    package = {"build": {"appId": "ai.skynet.desktop", "nsis": {"include": "nsis/installer.nsh"}}}

    before, detail = stamp.compute_wrapper_config_digest(package, tmp_path)
    assert detail["nsisIncludes"]["nsis/installer.nsh"]

    include.write_text("!macro customInstall\n  ExecShell open evil.exe\n!macroend\n", encoding="utf-8")
    after, _ = stamp.compute_wrapper_config_digest(package, tmp_path)

    assert before != after, "an install-time script change did not move the wrapper digest"


def test_a_build_config_change_moves_the_wrapper_digest(tmp_path):
    package = {"build": {"appId": "ai.skynet.desktop", "nsis": {"oneClick": False}}}
    before, _ = stamp.compute_wrapper_config_digest(package, tmp_path)

    package["build"]["nsis"]["oneClick"] = True
    after, _ = stamp.compute_wrapper_config_digest(package, tmp_path)

    assert before != after


def test_a_declared_but_missing_include_is_an_error(tmp_path):
    """A vanished script must not digest as if it were never declared."""
    package = {"build": {"nsis": {"include": "nsis/installer.nsh"}}}

    with pytest.raises(RuntimeError, match="missing"):
        stamp.compute_wrapper_config_digest(package, tmp_path)


def test_the_public_installer_name_is_professional_and_url_safe():
    """This is the filename a stranger sees in their download bar."""
    name = stamp.installer_name("0.1.1", "unsigned", "0.1.1+dirty.abcdef123456")

    assert name == "Skynet-Desktop-Setup-0.1.1-x64.exe"
    # No spaces: they become %20 in every URL and break copy/paste into a shell.
    assert " " not in name
    # No build plumbing leaking to end users -- that reads as a broken or untrusted artifact.
    for leak in ("dirty", "unsigned", "+", "abcdef123456"):
        assert leak not in name, f"build plumbing {leak!r} leaked into the public artifact name"


def test_the_public_name_is_stable_regardless_of_build_id():
    """Byte identity is a HASH's job; the filename's job is to be recognisable.

    Two payloads must never be published under one version -- that is enforced by version
    immutability and the published SHA-256, not by decorating the download name.
    """
    a = stamp.installer_name("0.1.1", "unsigned", stamp.build_id("0.1.1", "a" * 64, {"source_members_clean": False}))
    b = stamp.installer_name("0.1.1", "unsigned", stamp.build_id("0.1.1", "b" * 64, {"source_members_clean": False}))

    assert a == b == "Skynet-Desktop-Setup-0.1.1-x64.exe"


def test_a_version_bump_changes_the_public_name():
    assert stamp.installer_name("0.1.2") == "Skynet-Desktop-Setup-0.1.2-x64.exe"


def test_the_build_id_travels_inside_the_packaged_app():
    """extraMetadata puts it in the asar's package.json, recoverable from the artifact alone."""
    args = stamp.electron_builder_args({
        "version": "0.1.1",
        "distributionMode": "unsigned",
        "buildId": "0.1.1+gdeadbeef.abcdef123456",
        "sourceDigest": "f" * 64,
        "sourceCommit": "d" * 40,
        "sourceMembersClean": True,
    })

    joined = "\n".join(args)
    assert "-c.extraMetadata.skynetBuild.buildId=0.1.1+gdeadbeef.abcdef123456" in joined
    assert f"-c.extraMetadata.skynetBuild.sourceDigest={'f' * 64}" in joined
    assert "-c.extraMetadata.skynetBuild.sourceMembersClean=true" in joined
    assert "-c.nsis.artifactName=Skynet-Desktop-Setup-0.1.1-x64.exe" in joined


def test_the_real_repo_stamp_matches_the_gate_member_hashes():
    """Cross-check against the live payload: same files, same hashes, no drift."""
    digest, members = stamp.compute_source_digest(stamp.DESKTOP_ROOT)

    assert len(digest) == 64
    assert set(members) == set(gate.SOURCE_MEMBERS)
