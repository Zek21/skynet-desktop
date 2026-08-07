#!/usr/bin/env python3
"""Fail closed unless the canonical Windows desktop release is real and installable.

The release policy declares whether an artifact is signed or unsigned.  The unsigned
mode is deliberately explicit: it accepts only Authenticode ``NotSigned`` artifacts
and records that fact instead of implying publisher verification that does not exist.
"""

from __future__ import annotations

import contextlib
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any, Callable, ContextManager, Iterator


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# Digest helpers are shared with the build stamper so the gate verifies EXACTLY what the build
# recorded. A second private copy of the hashing rules would drift and certify the wrong bytes.
from tools import skynet_desktop_build_stamp as _build_stamp  # noqa: E402

DESKTOP_ROOT = ROOT / "desktop"
POLICY_PATH = DESKTOP_ROOT / "package.json"
PACKAGE_LOCK_PATH = DESKTOP_ROOT / "package-lock.json"
INSTALLER_ALLOWLIST_PATH = DESKTOP_ROOT / "release-installer-allowlist.json"
RULE1_ORDER_ROOT = ROOT / "data" / "lane_advisor_contract" / "cdp_local_evidence" / "rule1_work_orders"
CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3"
APPLICATION_NAME = "Skynet Desktop.exe"
# Errors that make the empirical install audit UNSAFE or IMPOSSIBLE to run: the payload could
# not be extracted, or the bytes on disk are not the bytes the gate verified. Executing an
# installer in that state would be running an unverified binary, so these -- and ONLY these --
# still skip the audit. A PAPERWORK failure (an unapproved allowlist re-bind) must never
# suppress empirical verification; see the accumulate-all-errors comment at the audit site.
EMPIRICAL_AUDIT_BLOCKERS = frozenset({
    "installer_payload_verification_failed",
    "installer_application_hash_mismatch",
    "installer_app_asar_hash_mismatch",
    "electron_identity_verification_failed",
    "artifact_signer_mismatch",
})
SOURCE_MEMBERS = (
    "main.js",
    "preload.js",
    "lib/cli_provisioning.js",
    "lib/portable_runtime.js",
    "lib/sidecar_runtime.js",
    "renderer/index.html",
    "renderer/app.js",
    "renderer/app.css",
    # The support QR is a REVIEWED payload member on purpose: it encodes a payment URL, so an
    # unreviewed swap here would silently redirect sponsors. Its bytes are hash-pinned like code.
    "renderer/support-qr.png",
    "build/icon.ico",
    "build/icon.png",
)
EXPECTED_ASAR_MEMBERS = frozenset({"package.json", *SOURCE_MEMBERS})
REQUIRED_INSTALLER_ENTRIES = {
    APPLICATION_NAME,
    "resources/app.asar",
    "chrome_100_percent.pak",
    "LICENSES.chromium.html",
    "v8_context_snapshot.bin",
}
# Files electron-builder adds to the packaged tree that are NOT part of the Electron
# runtime. Each is pinned to the exact bytes shipped by the electron-builder NSIS
# toolchain, verified against %LOCALAPPDATA%\electron-builder\Cache\nsis-3.0.4.1, so the
# exemption cannot be used to slip in a different binary under the same name.
ELECTRON_BUILDER_EXPECTED_EXTRAS = {
    # UAC elevation helper, byte-identical to nsis-3.0.4.1/elevate.exe (107,520 bytes).
    "resources/elevate.exe": "9b1fbf0c11c520ae714af8aa9af12cfd48503eedecd7398d8992ee94d1b4dc37",
}

# The ONE acceptable byte sequence for desktop/package-lock.json. Reviewing a 64-character
# digest is possible through the advisor channel; rendering the 127,433-byte file is not.
PINNED_PACKAGE_LOCK_SHA256 = "67e5bff509e4a1fb30474b512157bdc6976970803025ce074bdcc1514ea78125"

PINNED_NPM_ARTIFACTS = {
    "electron": {
        "version": "43.2.0",
        "resolved": "https://registry.npmjs.org/electron/-/electron-43.2.0.tgz",
        "integrity": "sha512-80zvrgG7ZRXD+tD0IyLvrnN9n+veSxadMRsMaC9wKKP3iUbtC7rGM8+dVuCmOb0Rrwwv8ESW4awnUZh9Hbp1fA==",
    },
    "electron_builder": {
        "version": "26.15.3",
        "resolved": "https://registry.npmjs.org/electron-builder/-/electron-builder-26.15.3.tgz",
        "integrity": "sha512-a1KM5heqS3gQCZzizXEI8RjJy3QVogULPdeSknt76uLDpBIW/HDGsMg/XgP0riP6PI9COsRvFITKKGDqA8fJxA==",
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normalized_thumbprint(value: object) -> str:
    return re.sub(r"[^0-9A-F]", "", str(value or "").upper())


def _common_name(subject: str) -> str:
    match = re.search(r"(?:^|,\s*)CN=([^,]+)", subject, flags=re.IGNORECASE)
    return match.group(1).strip() if match else subject.strip()


def _publisher_matches(expected: str, subject: str) -> bool:
    wanted = expected.strip().casefold()
    return bool(wanted) and wanted in {
        subject.strip().casefold(),
        _common_name(subject).casefold(),
    }


def load_release_package(path: Path = POLICY_PATH) -> dict[str, Any]:
    resolved = path.resolve()
    if resolved != POLICY_PATH.resolve():
        raise RuntimeError("release policy must be the canonical desktop/package.json")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("canonical package policy is not an object")
    return payload


def load_release_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    package = load_release_package(path)
    policy = package.get("skynetRelease")
    return policy if isinstance(policy, dict) else {}


def load_release_package_lock(path: Path = PACKAGE_LOCK_PATH) -> dict[str, Any]:
    resolved = path.resolve()
    if resolved != PACKAGE_LOCK_PATH.resolve():
        raise RuntimeError("release lock must be the canonical desktop/package-lock.json")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("canonical package lock is not an object")
    return payload


def verify_package_lock_bytes(path: Path = PACKAGE_LOCK_PATH) -> dict[str, Any]:
    """Bind the WHOLE lockfile by hash, not just its two direct dependency entries.

    Pinning only `node_modules/electron` and `node_modules/electron-builder` constrains
    neither the other ~283 package entries nor any dependency edge between them, so a
    regenerated or edited tree could satisfy every other check while differing
    arbitrarily. A single whole-file digest closes that: exactly one byte sequence is
    acceptable, and it is a 64-character constant that can be reviewed directly rather
    than a 127 KB file that cannot be rendered for review.

    Regenerating the lock with npm is therefore NOT sufficient on its own -- the result
    must hash to this exact value or the gate fails closed.
    """
    resolved = path.resolve()
    if resolved != PACKAGE_LOCK_PATH.resolve():
        raise RuntimeError("release lock must be the canonical desktop/package-lock.json")
    if not resolved.is_file():
        return {"ok": False, "errors": ["package_lock_missing"], "expected": PINNED_PACKAGE_LOCK_SHA256}
    actual = _sha256(resolved)
    errors = [] if actual == PINNED_PACKAGE_LOCK_SHA256 else ["package_lock_whole_file_hash_mismatch"]
    return {
        "ok": not errors,
        "expected": PINNED_PACKAGE_LOCK_SHA256,
        "actual": actual,
        "bytes": resolved.stat().st_size,
        "errors": errors,
    }


def verify_package_lock_identity(package: dict[str, Any], package_lock: dict[str, Any]) -> dict[str, Any]:
    root = package_lock.get("packages", {}).get("") if isinstance(package_lock.get("packages"), dict) else {}
    root = root if isinstance(root, dict) else {}
    packages = package_lock.get("packages") if isinstance(package_lock.get("packages"), dict) else {}
    policy = package.get("skynetRelease") if isinstance(package.get("skynetRelease"), dict) else {}
    expected_electron = str(policy.get("electronVersion") or "")
    expected_builder = str(policy.get("electronBuilderVersion") or "")
    errors = []
    if package_lock.get("lockfileVersion") != 3 or package_lock.get("requires") is not True:
        errors.append("package_lock_format_mismatch")
    if package_lock.get("name") != package.get("name") or root.get("name") != package.get("name"):
        errors.append("package_lock_name_mismatch")
    if package_lock.get("version") != package.get("version") or root.get("version") != package.get("version"):
        errors.append("package_lock_version_mismatch")
    if root.get("devDependencies") != package.get("devDependencies"):
        errors.append("package_lock_dev_dependencies_mismatch")
    resolved_electron = packages.get("node_modules/electron", {})
    resolved_builder = packages.get("node_modules/electron-builder", {})
    if not isinstance(resolved_electron, dict) or resolved_electron.get("version") != expected_electron:
        errors.append("package_lock_electron_resolution_mismatch")
    if not isinstance(resolved_builder, dict) or resolved_builder.get("version") != expected_builder:
        errors.append("package_lock_builder_resolution_mismatch")
    for name, row in (("electron", resolved_electron), ("electron_builder", resolved_builder)):
        pinned = PINNED_NPM_ARTIFACTS[name]
        if not isinstance(row, dict) or row.get("version") != pinned["version"]:
            errors.append(f"package_lock_{name}_pinned_version_mismatch")
        if not isinstance(row, dict) or row.get("resolved") != pinned["resolved"]:
            errors.append(f"package_lock_{name}_pinned_tarball_mismatch")
        if not isinstance(row, dict) or row.get("integrity") != pinned["integrity"]:
            errors.append(f"package_lock_{name}_pinned_integrity_mismatch")
    return {
        "ok": not errors,
        "lockfile_version": package_lock.get("lockfileVersion"),
        "resolved_electron": resolved_electron.get("version") if isinstance(resolved_electron, dict) else None,
        "resolved_electron_builder": resolved_builder.get("version") if isinstance(resolved_builder, dict) else None,
        "errors": errors,
    }


def _package_contract_errors(package: dict[str, Any]) -> list[str]:
    build = package.get("build") if isinstance(package.get("build"), dict) else {}
    win = build.get("win") if isinstance(build.get("win"), dict) else {}
    nsis = build.get("nsis") if isinstance(build.get("nsis"), dict) else {}
    scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
    policy = package.get("skynetRelease") if isinstance(package.get("skynetRelease"), dict) else {}
    distribution_mode = str(policy.get("distributionMode") or "")
    checks = {
        "package_name_mismatch": package.get("name") == "skynet-desktop",
        "product_name_mismatch": package.get("productName") == "Skynet Desktop",
        "main_entry_mismatch": package.get("main") == "main.js",
        "version_invalid": bool(re.fullmatch(r"\d+\.\d+\.\d+", str(package.get("version") or ""))),
        "app_id_mismatch": build.get("appId") == "ai.skynet.desktop",
        "distribution_mode_invalid": distribution_mode in {"unsigned", "signed"},
        "force_code_signing_mismatch": build.get("forceCodeSigning") is (distribution_mode == "signed"),
        "asar_required": build.get("asar") is True,
        "packaged_file_allowlist_mismatch": build.get("files") == [
            "main.js", "preload.js", "lib/**/*", "renderer/**/*", "build/**/*"
        ],
        "extra_resources_forbidden": build.get("extraResources", []) == [],
        "executable_name_mismatch": win.get("executableName") == "Skynet Desktop",
        "windows_target_mismatch": win.get("target") == ["nsis"],
        "shortcut_name_mismatch": nsis.get("shortcutName") == "Skynet Desktop",
        # Professional, URL-safe public artifact name. No spaces (they become %20 in every
        # download URL) and no build plumbing -- see skynet_desktop_build_stamp.installer_name.
        "installer_name_mismatch": nsis.get("artifactName") == "Skynet-Desktop-Setup-${version}-x64.${ext}",
        "desktop_shortcut_required": nsis.get("createDesktopShortcut") is True,
        "start_menu_shortcut_required": nsis.get("createStartMenuShortcut") is True,
        "per_user_install_required": nsis.get("perMachine") is False,
        "assisted_installer_required": nsis.get("oneClick") is False,
        "installation_directory_choice_required": nsis.get("allowToChangeInstallationDirectory") is True,
        "run_after_finish_required": nsis.get("runAfterFinish") is True,
        "release_shortcut_mismatch": policy.get("shortcutName") == "Skynet Desktop",
        "release_app_id_mismatch": policy.get("appUserModelId") == build.get("appId") == "ai.skynet.desktop",
        "electron_version_invalid": bool(re.fullmatch(r"\d+\.\d+\.\d+", str(policy.get("electronVersion") or ""))),
        "electron_dependency_mismatch": str(package.get("devDependencies", {}).get("electron") or "").lstrip("^") == str(policy.get("electronVersion") or ""),
        "electron_builder_version_invalid": bool(re.fullmatch(r"\d+\.\d+\.\d+", str(policy.get("electronBuilderVersion") or ""))),
        "electron_builder_dependency_mismatch": str(package.get("devDependencies", {}).get("electron-builder") or "").lstrip("^") == str(policy.get("electronBuilderVersion") or ""),
        "electron_reference_exe_hash_invalid": bool(re.fullmatch(r"[0-9a-f]{64}", str(policy.get("electronReferenceExeSha256") or ""))),
        "electron_reference_tree_hash_invalid": bool(re.fullmatch(r"[0-9a-f]{64}", str(policy.get("electronReferenceTreeSha256") or ""))),
        "release_verifier_not_canonical": scripts.get("verify:release") == "python ../tools/skynet_desktop_release_gate.py",
        # The canonical build goes through the STAMPING driver, not bare electron-builder: a
        # raw `electron-builder --win` produces an artifact identified only by its version
        # string, which is how two different payloads both shipped as 0.1.1.
        "installer_builder_not_canonical": scripts.get("build:installer") == "python ../tools/skynet_desktop_build.py",
        # The install-time NSIS script is part of what approval binds (wrapperConfigDigest), so
        # it must stay declared at the reviewed path -- dropping the include would silently
        # change what the wrapper does.
        "nsis_include_not_canonical": nsis.get("include") == "nsis/installer.nsh",
        "pack_requires_live_gate": scripts.get("pack") == "npm run build:installer && npm run verify:release",
        # An unsigned release must be unsigned by CONFIGURATION, not merely unforced.
        # forceCodeSigning=False only declines to REQUIRE a signature; electron-builder
        # would still sign if it discovered a certificate. signExecutable=False is the
        # documented Windows switch that skips signing while keeping resource editing,
        # which the PE identity checks depend on.
        "unsigned_release_does_not_disable_signing": (
            build.get("win", {}).get("signExecutable") is False
            if str(policy.get("distributionMode") or "") == "unsigned" else True
        ),
    }
    return [error for error, valid in checks.items() if not valid]


def load_installer_allowlist(path: Path = INSTALLER_ALLOWLIST_PATH) -> tuple[dict[str, Any], str]:
    if path.resolve() != INSTALLER_ALLOWLIST_PATH.resolve():
        raise RuntimeError("installer allowlist must be desktop/release-installer-allowlist.json")
    _validate_regular_source_path(path, DESKTOP_ROOT)
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("installer allowlist is not an object")
    return payload, _bytes_sha256(raw)


def _find_committed_allowlist_receipt(allowlist_sha256: str) -> dict[str, Any]:
    if not RULE1_ORDER_ROOT.is_dir():
        raise RuntimeError("Rule 1 work-order root is unavailable")
    expected_target = _norm_windows_path(INSTALLER_ALLOWLIST_PATH.resolve())
    matches = []
    for order_dir in RULE1_ORDER_ROOT.iterdir():
        if not order_dir.is_dir() or not re.fullmatch(r"rule1_[0-9A-Za-z_]+", order_dir.name):
            continue
        state_path = order_dir / "state.json"
        request_path = order_dir / "request.json"
        if not state_path.is_file() or not request_path.is_file():
            continue
        try:
            _validate_regular_source_path(state_path, RULE1_ORDER_ROOT)
            _validate_regular_source_path(request_path, RULE1_ORDER_ROOT)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            request = json.loads(request_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if state.get("state") != "COMMITTED" or state.get("authorized") is not True:
            continue
        if state.get("intent_sha256") != request.get("intent_sha256"):
            continue
        unsigned_request = dict(request)
        recorded_intent = str(unsigned_request.pop("intent_sha256", ""))
        # ensure_ascii=False is REQUIRED, not cosmetic: it is the canonical form
        # skynet_rule1_work_order._canonical() hashes with.  Re-deriving with the
        # json.dumps default (ensure_ascii=True) escapes every non-ASCII character to
        # \uXXXX, so the bytes differ and the intent never matches -- silently, and only
        # for orders whose text happens to contain a non-ASCII character such as an em
        # dash.  That made a genuinely COMMITTED, dual-approved order unusable here while
        # ASCII-only orders validated fine.  Producer and verifier must agree on one form.
        computed_intent = hashlib.sha256(
            json.dumps(
                unsigned_request, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        if not recorded_intent or computed_intent != recorded_intent:
            continue
        for action in request.get("proposed_actions", []):
            arguments = action.get("arguments") if isinstance(action, dict) else {}
            if (
                action.get("tool") == "copy_file"
                and _norm_windows_path(arguments.get("path")) == expected_target
                and arguments.get("source_sha256") == allowlist_sha256
            ):
                matches.append({
                    "order_id": order_dir.name,
                    "intent_sha256": request.get("intent_sha256"),
                    "state": state.get("state"),
                })
    if len(matches) != 1:
        raise RuntimeError(
            f"installer allowlist needs exactly one committed dual-approval receipt, found {len(matches)}"
        )
    return matches[0]


def _verify_source_bound_allowlist(
    installer: Path,
    package: dict[str, Any],
    allowlist: dict[str, Any],
    allowlist_sha256: str,
    receipt_finder: Callable[[str], dict[str, Any]],
    source_root: Path,
) -> dict[str, Any]:
    """Approve the reviewable SOURCE, then derive the wrapper mechanically.

    Why this schema exists: the /1 allowlist binds the 99.7MB NSIS wrapper's sha256, so
    approving a rebuild means reviewing a 99.7MB binary. That is not reviewable through any
    chat/review channel, which deadlocked six approval rounds -- a channel limit, not an
    evidence-quality problem. CDP advisor (Gemini 3.6 Thinking, 2026-08-07) ranked it a BLOCKER
    and prescribed moving approval upstream to reviewable source plus automated attestation.

    The chain is sound because the gate ALREADY proves, mechanically, that the wrapper carries
    exactly the reviewed payload: verify_asar_identity pins the asar's member set and hashes
    against these same source files, payload_binding proves the installer-embedded asar and
    application match the built ones, and verify_complete_payload_tree proves the extracted
    tree matches file-for-file. What that chain could NOT cover is install-time NSIS behaviour,
    which is why wrapperConfigDigest is bound too: it hashes the declarative build config plus
    every declared nsis include, so the wrapper's actions are reviewable as a few KB of text.

    Together these bind ~300KB of reviewable text instead of a 99.7MB opaque blob, with no
    weakening -- every hash below is recomputed from disk, and any mismatch fails closed.
    """
    errors: list[str] = []
    policy = package.get("skynetRelease") if isinstance(package.get("skynetRelease"), dict) else {}
    version = str(package.get("version") or "")
    expected = {
        "schema": "skynet_desktop_installer_allowlist/2",
        "productName": "Skynet Desktop",
        "version": version,
        "distributionMode": policy.get("distributionMode"),
        # The public artifact name is approved EXPLICITLY. It used to be checked by requiring
        # the source digest to appear inside the filename, which forced build plumbing into a
        # name end users see. Binding the name as its own field keeps the artifact
        # professionally named while still pinning exactly which file was approved.
        "installerName": _build_stamp.installer_name(version, policy.get("distributionMode")),
    }
    if set(allowlist) != {*expected, "sourceDigest", "wrapperConfigDigest"}:
        errors.append("installer_allowlist_fields_not_exact")
    for key, value in expected.items():
        if allowlist.get(key) != value:
            errors.append(f"installer_allowlist_{key}_mismatch")

    approved_source = str(allowlist.get("sourceDigest") or "")
    approved_wrapper = str(allowlist.get("wrapperConfigDigest") or "")
    actual_source = actual_wrapper = ""
    try:
        actual_source, _ = _build_stamp.compute_source_digest(source_root)
        actual_wrapper, _ = _build_stamp.compute_wrapper_config_digest(package, source_root)
    except Exception as exc:
        errors.append(f"installer_allowlist_digest_recompute_failed:{type(exc).__name__}")
    if not re.fullmatch(r"[0-9a-f]{64}", approved_source) or not re.fullmatch(r"[0-9a-f]{64}", approved_wrapper):
        errors.append("installer_allowlist_digest_invalid")
    if not actual_source or actual_source != approved_source:
        errors.append("installer_source_digest_not_approved")
    if not actual_wrapper or actual_wrapper != approved_wrapper:
        errors.append("installer_wrapper_config_not_approved")

    # The file on disk must be the file that was approved.
    if installer.name != allowlist.get("installerName"):
        errors.append("installer_name_not_approved")

    receipt: dict[str, Any] = {}
    try:
        receipt = receipt_finder(allowlist_sha256)
    except Exception as exc:
        errors.append(f"installer_allowlist_receipt_invalid:{type(exc).__name__}:{exc}")
    return {
        "ok": not errors,
        "binding": "source_digest",
        "allowlist_path": str(INSTALLER_ALLOWLIST_PATH),
        "allowlist_sha256": allowlist_sha256,
        "approved_source_digest": approved_source,
        "actual_source_digest": actual_source,
        "approved_wrapper_config_digest": approved_wrapper,
        "actual_wrapper_config_digest": actual_wrapper,
        "actual_installer_sha256": _sha256(installer) if installer.is_file() else "",
        "approval_receipt": receipt,
        "errors": errors,
    }


def verify_installer_allowlist(
    installer: Path,
    package: dict[str, Any],
    allowlist: dict[str, Any],
    allowlist_sha256: str,
    receipt_finder: Callable[[str], dict[str, Any]] = _find_committed_allowlist_receipt,
    source_root: Path = DESKTOP_ROOT,
) -> dict[str, Any]:
    # Schema /2 binds reviewable source; /1 binds the wrapper blob hash. Both fail closed, and
    # an unrecognised schema is rejected rather than defaulting to the weaker check.
    if allowlist.get("schema") == "skynet_desktop_installer_allowlist/2":
        return _verify_source_bound_allowlist(
            installer, package, allowlist, allowlist_sha256, receipt_finder, source_root
        )
    policy = package.get("skynetRelease") if isinstance(package.get("skynetRelease"), dict) else {}
    version = str(package.get("version") or "")
    # One canonical public artifact name, shared with the build stamper and the /2 path, so the
    # name the gate approves is always the name the build actually produces.
    expected_name = _build_stamp.installer_name(version, policy.get("distributionMode"))
    expected = {
        "schema": "skynet_desktop_installer_allowlist/1",
        "productName": "Skynet Desktop",
        "version": version,
        "distributionMode": policy.get("distributionMode"),
        "installerName": expected_name,
    }
    errors = []
    if set(allowlist) != {*expected, "installerSha256"}:
        errors.append("installer_allowlist_fields_not_exact")
    for key, value in expected.items():
        if allowlist.get(key) != value:
            errors.append(f"installer_allowlist_{key}_mismatch")
    approved_hash = str(allowlist.get("installerSha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", approved_hash):
        errors.append("installer_allowlist_hash_invalid")
    actual_hash = _sha256(installer) if installer.is_file() else ""
    if actual_hash != approved_hash:
        errors.append("installer_wrapper_hash_not_dual_approved")
    receipt: dict[str, Any] = {}
    try:
        receipt = receipt_finder(allowlist_sha256)
    except Exception as exc:
        errors.append(f"installer_allowlist_receipt_invalid:{type(exc).__name__}:{exc}")
    return {
        "ok": not errors,
        "allowlist_path": str(INSTALLER_ALLOWLIST_PATH),
        "allowlist_sha256": allowlist_sha256,
        "approved_installer_sha256": approved_hash,
        "actual_installer_sha256": actual_hash,
        "approval_receipt": receipt,
        "errors": errors,
    }


def _powershell() -> str:
    executable = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not executable:
        raise RuntimeError("PowerShell is required for Windows release verification")
    return executable


def _powershell_signature(path: Path) -> dict[str, Any]:
    script = r"""
$ErrorActionPreference = 'Stop'
$sig = Get-AuthenticodeSignature -LiteralPath $env:SKYNET_DESKTOP_RELEASE_ARTIFACT
$oids = @()
if ($null -ne $sig.SignerCertificate) {
  foreach ($extension in $sig.SignerCertificate.Extensions) {
    if ($extension.Oid.Value -eq '2.5.29.37') {
      foreach ($usage in $extension.EnhancedKeyUsages) { $oids += [string]$usage.Value }
    }
  }
}
[ordered]@{
  status = [string]$sig.Status
  status_message = [string]$sig.StatusMessage
  signature_type = [string]$sig.SignatureType
  signer_subject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }
  signer_issuer = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Issuer } else { '' }
  signer_thumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { '' }
  signer_not_after = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotAfter.ToUniversalTime().ToString('o') } else { '' }
  timestamper_subject = if ($sig.TimeStamperCertificate) { [string]$sig.TimeStamperCertificate.Subject } else { '' }
  timestamper_thumbprint = if ($sig.TimeStamperCertificate) { [string]$sig.TimeStamperCertificate.Thumbprint } else { '' }
  enhanced_key_usage_oids = @($oids)
} | ConvertTo-Json -Compress -Depth 4
"""
    env = os.environ.copy()
    env["SKYNET_DESKTOP_RELEASE_ARTIFACT"] = str(path)
    completed = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:1000]
        raise RuntimeError(f"Authenticode probe failed: {detail}")
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("Authenticode probe returned a non-object payload")
    return payload


def _powershell_version_info(path: Path) -> dict[str, str]:
    script = r"""
$ErrorActionPreference = 'Stop'
$v = (Get-Item -LiteralPath $env:SKYNET_DESKTOP_RELEASE_ARTIFACT).VersionInfo
[ordered]@{
  file_description = [string]$v.FileDescription
  product_name = [string]$v.ProductName
  internal_name = [string]$v.InternalName
  product_version = [string]$v.ProductVersion
} | ConvertTo-Json -Compress
"""
    env = os.environ.copy()
    env["SKYNET_DESKTOP_RELEASE_ARTIFACT"] = str(path)
    completed = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"version-info probe failed: {(completed.stderr or completed.stdout)[-1000:]}")
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("version-info probe returned a non-object payload")
    return {str(key): str(value or "") for key, value in payload.items()}


def _resolve_7zip(expected_sha256: str) -> Path:
    expected = str(expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("release policy requires an anchored sevenZipSha256")
    candidates: list[Path] = []
    for command in ("7za.exe", "7z.exe", "7zz.exe"):
        found = shutil.which(command)
        if found:
            candidates.append(Path(found))
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        cache = Path(local_app_data) / "electron-builder" / "Cache"
        if cache.is_dir():
            candidates.extend(cache.glob("**/7za.exe"))
    candidates.extend(ROOT.glob("desktop/node_modules/**/7za.exe"))
    for candidate in dict.fromkeys(path.resolve() for path in candidates if path.is_file()):
        if _sha256(candidate) == expected:
            return candidate
    raise RuntimeError("no 7-Zip extractor matched the reviewed release-policy hash")


def _installer_entries(seven_zip: Path, installer: Path) -> set[str]:
    completed = subprocess.run(
        [str(seven_zip), "l", "-slt", str(installer)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"7-Zip list failed ({completed.returncode}): {(completed.stderr or completed.stdout)[-1000:]}")
    entries = set()
    for line in completed.stdout.splitlines():
        if line.startswith("Path = "):
            value = line[7:].replace("\\", "/")
            if value and value != str(installer).replace("\\", "/"):
                entries.add(value)
    return entries


def _extract_installer_members(
    seven_zip: Path,
    installer: Path,
    target: Path,
    members: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        [str(seven_zip), "x", "-y", f"-o{target}", str(installer), *members],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"7-Zip extraction failed ({completed.returncode}): {(completed.stderr or completed.stdout)[-1000:]}")


@contextlib.contextmanager
def extracted_installer_payload(installer: Path, policy: dict[str, Any]) -> Iterator[dict[str, Path]]:
    seven_zip = _resolve_7zip(str(policy.get("sevenZipSha256") or ""))
    entries = _installer_entries(seven_zip, installer)
    missing = sorted(REQUIRED_INSTALLER_ENTRIES - entries)
    if missing:
        raise RuntimeError("installer is missing Electron payload entries: " + ", ".join(missing))
    with tempfile.TemporaryDirectory(prefix="skynet-desktop-release-") as raw_temp:
        target = Path(raw_temp)
        _extract_installer_members(seven_zip, installer, target, ())
        application = target / APPLICATION_NAME
        app_asar = target / "resources" / "app.asar"
        if not application.is_file() or not app_asar.is_file():
            raise RuntimeError("installer extraction did not produce the Electron app and app.asar")
        yield {"application": application, "app_asar": app_asar}


def _metadata_has_windows_reparse_point(
    metadata: os.stat_result, path: object, *, require_windows_metadata: bool | None = None
) -> bool:
    require_metadata = os.name == "nt" if require_windows_metadata is None else require_windows_metadata
    attributes = getattr(metadata, "st_file_attributes", None)
    reparse_tag = int(getattr(metadata, "st_reparse_tag", 0) or 0)
    if require_metadata and attributes is None:
        raise RuntimeError(f"Windows reparse metadata is unavailable for {path}")
    return bool((int(attributes or 0) & 0x400) or reparse_tag)


def _entry_has_windows_reparse_point(
    entry: os.DirEntry[str], *, require_windows_metadata: bool | None = None
) -> bool:
    return _metadata_has_windows_reparse_point(
        entry.stat(follow_symlinks=False),
        entry.path,
        require_windows_metadata=require_windows_metadata,
    )


def _path_has_windows_reparse_point(
    path: Path, *, require_windows_metadata: bool | None = None
) -> bool:
    return _metadata_has_windows_reparse_point(
        os.lstat(path), path, require_windows_metadata=require_windows_metadata
    )


def _validate_regular_source_path(path: Path, source_root: Path) -> None:
    try:
        relative = path.relative_to(source_root)
    except ValueError as exc:
        raise RuntimeError(f"canonical source escapes its root: {path}") from exc
    components = [source_root]
    current = source_root
    for part in relative.parts:
        current = current / part
        components.append(current)
    for index, component in enumerate(components):
        try:
            metadata = os.lstat(component)
        except FileNotFoundError as exc:
            raise RuntimeError(f"canonical Electron source is missing: {relative.as_posix()}") from exc
        is_junction = bool(getattr(component, "is_junction", lambda: False)())
        if component.is_symlink() or is_junction or _metadata_has_windows_reparse_point(metadata, component):
            raise RuntimeError(f"canonical Electron source path contains a reparse point: {component}")
        if index < len(components) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"canonical Electron source parent is not a directory: {component}")
        if index == len(components) - 1 and not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"canonical Electron source is not a regular file: {relative.as_posix()}")


def _tree_snapshot(root: Path) -> tuple[dict[str, str], set[str]]:
    try:
        root_metadata = os.lstat(root)
    except FileNotFoundError as exc:
        raise RuntimeError(f"application tree is missing: {root}") from exc
    root_is_junction = bool(getattr(root, "is_junction", lambda: False)())
    if root.is_symlink() or root_is_junction or _metadata_has_windows_reparse_point(root_metadata, root):
        raise RuntimeError(f"application tree root is a link, junction, or reparse point: {root}")
    if not root.is_dir():
        raise RuntimeError(f"application tree is missing: {root}")
    files: dict[str, str] = {}
    directories: set[str] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                is_junction = bool(getattr(path, "is_junction", lambda: False)())
                is_reparse_point = _entry_has_windows_reparse_point(entry)
                if entry.is_symlink() or is_junction or is_reparse_point:
                    raise RuntimeError(
                        f"application tree contains a link, junction, or reparse point: {relative}"
                    )
                if entry.is_dir(follow_symlinks=False):
                    directories.add(relative)
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    files[relative] = _sha256(path)
                else:
                    raise RuntimeError(f"application tree contains a non-regular entry: {relative}")
    return files, directories


def _tree_hashes(root: Path) -> dict[str, str]:
    return _tree_snapshot(root)[0]


def verify_complete_payload_tree(
    loose_root: Path,
    candidate_root: Path,
    *,
    allowed_extra: set[str] | None = None,
) -> dict[str, Any]:
    loose, loose_directories = _tree_snapshot(loose_root)
    candidate, candidate_directories = _tree_snapshot(candidate_root)
    missing = sorted(set(loose) - set(candidate))
    mismatched = sorted(name for name in loose.keys() & candidate.keys() if loose[name] != candidate[name])
    extra = sorted(set(candidate) - set(loose))
    allowed = {Path(name).as_posix() for name in (allowed_extra or set())}
    unexpected_extra = sorted(set(extra) - allowed)
    missing_directories = sorted(loose_directories - candidate_directories)
    extra_directories = sorted(candidate_directories - loose_directories)
    return {
        "ok": not missing and not mismatched and not unexpected_extra and not missing_directories and not extra_directories,
        "loose_file_count": len(loose),
        "candidate_file_count": len(candidate),
        "missing": missing,
        "mismatched": mismatched,
        "extra": extra,
        "allowed_extra": sorted(allowed),
        "unexpected_extra": unexpected_extra,
        "missing_directories": missing_directories,
        "extra_directories": extra_directories,
        "loose_tree_sha256": hashlib.sha256(
            json.dumps(loose, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _asar_member(data: bytes, header: dict[str, Any], data_start: int, member: str) -> bytes:
    node: Any = header
    for part in member.split("/"):
        files = node.get("files") if isinstance(node, dict) else None
        node = files.get(part) if isinstance(files, dict) else None
        if not isinstance(node, dict):
            raise RuntimeError(f"app.asar missing reviewed source member: {member}")
    if node.get("unpacked") or node.get("link") is not None or "files" in node:
        raise RuntimeError(f"app.asar member is not an inline regular file: {member}")
    size = node.get("size")
    offset = node.get("offset")
    if not isinstance(size, int) or size < 0 or not str(offset).isdigit():
        raise RuntimeError(f"app.asar member has an invalid descriptor: {member}")
    begin = data_start + int(offset)
    end = begin + size
    if begin < data_start or end > len(data):
        raise RuntimeError(f"app.asar member exceeds archive bounds: {member}")
    content = data[begin:end]
    integrity = node.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA256":
        raise RuntimeError(f"app.asar member lacks SHA256 integrity metadata: {member}")
    if str(integrity.get("hash") or "").lower() != _bytes_sha256(content):
        raise RuntimeError(f"app.asar integrity mismatch: {member}")
    return content


def _asar_file_descriptors(header: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return every archive member and reject links, unpacked bytes, and odd nodes."""

    found: dict[str, dict[str, Any]] = {}

    def walk(node: dict[str, Any], prefix: str = "") -> None:
        files = node.get("files")
        if not isinstance(files, dict):
            raise RuntimeError(f"app.asar directory has no files map: {prefix or '/'}")
        for raw_name, descriptor in files.items():
            name = str(raw_name)
            if not name or "/" in name or "\\" in name or name in {".", ".."}:
                raise RuntimeError(f"app.asar contains an invalid member name: {name!r}")
            if not isinstance(descriptor, dict):
                raise RuntimeError(f"app.asar member descriptor is invalid: {prefix}{name}")
            member = f"{prefix}{name}"
            if descriptor.get("unpacked") or descriptor.get("link") is not None:
                raise RuntimeError(f"app.asar contains unpacked or linked content: {member}")
            if "files" in descriptor:
                walk(descriptor, member + "/")
            else:
                found[member] = descriptor

    walk(header)
    return found


def _verify_asar_data_coverage(
    data: bytes,
    header: dict[str, Any],
    data_start: int,
    descriptors: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    ranges: list[tuple[int, int, str]] = []
    for member, descriptor in descriptors.items():
        _asar_member(data, header, data_start, member)
        size = int(descriptor["size"])
        begin = data_start + int(descriptor["offset"])
        ranges.append((begin, begin + size, member))
    ranges.sort(key=lambda row: (row[0], row[1], row[2]))
    cursor = data_start
    for begin, end, member in ranges:
        if begin != cursor:
            relation = "overlap" if begin < cursor else "gap"
            raise RuntimeError(f"app.asar data ranges contain a {relation} before {member}")
        cursor = end
    if cursor != len(data):
        relation = "trailing unreferenced bytes" if cursor < len(data) else "range beyond archive"
        raise RuntimeError(f"app.asar data coverage failed: {relation}")
    return {
        "member_count": len(ranges),
        "data_start": data_start,
        "data_end": cursor,
        "archive_size": len(data),
        "complete_nonoverlapping_coverage": True,
    }


def verify_asar_identity(
    app_asar: Path,
    package: dict[str, Any],
    source_root: Path = DESKTOP_ROOT,
) -> dict[str, Any]:
    data = app_asar.read_bytes()
    if len(data) < 16 or struct.unpack_from("<I", data, 0)[0] != 4:
        raise RuntimeError("app.asar has an invalid outer header")
    header_size = struct.unpack_from("<I", data, 4)[0]
    inner_size = struct.unpack_from("<I", data, 8)[0]
    json_size = struct.unpack_from("<I", data, 12)[0]
    data_start = 8 + header_size
    if header_size != inner_size + 4 or inner_size < json_size + 4 or data_start > len(data):
        raise RuntimeError("app.asar header sizes are inconsistent")
    try:
        header = json.loads(data[16:16 + json_size].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"app.asar header JSON is invalid: {exc}") from exc
    if not isinstance(header, dict):
        raise RuntimeError("app.asar header JSON is not an object")
    descriptors = _asar_file_descriptors(header)
    actual_members = set(descriptors)
    missing_members = sorted(EXPECTED_ASAR_MEMBERS - actual_members)
    extra_members = sorted(actual_members - EXPECTED_ASAR_MEMBERS)
    if missing_members or extra_members:
        raise RuntimeError(
            "app.asar member set differs from the reviewed package "
            f"(missing={missing_members}, extra={extra_members})"
        )
    coverage = _verify_asar_data_coverage(data, header, data_start, descriptors)
    packaged_manifest = json.loads(_asar_member(data, header, data_start, "package.json").decode("utf-8"))
    required_manifest = {
        "name": "skynet-desktop",
        "productName": "Skynet Desktop",
        "version": package.get("version"),
        "main": "main.js",
        "private": True,
    }
    if not isinstance(packaged_manifest, dict) or any(
        packaged_manifest.get(key) != value for key, value in required_manifest.items()
    ):
        raise RuntimeError("app.asar package identity does not match the canonical Electron product")
    members: dict[str, dict[str, Any]] = {}
    for member in SOURCE_MEMBERS:
        source = source_root / Path(member)
        _validate_regular_source_path(source, source_root)
        content = _asar_member(data, header, data_start, member)
        source_hash = _sha256(source)
        packaged_hash = _bytes_sha256(content)
        if source_hash != packaged_hash:
            raise RuntimeError(f"packaged Electron source differs from reviewed repository bytes: {member}")
        members[member] = {"bytes": len(content), "sha256": packaged_hash}
    return {
        "ok": True,
        "archive_sha256": _sha256(app_asar),
        "manifest": required_manifest,
        "all_members": sorted(actual_members),
        "data_coverage": coverage,
        "source_members": members,
    }


def _evaluate_artifact(
    path: Path,
    distribution_mode: str,
    expected_publisher: str,
    allowed_thumbprints: set[str],
    expected_name: str,
    signature_loader: Callable[[Path], dict[str, Any]],
) -> dict[str, Any]:
    errors: list[str] = []
    if not path.is_file():
        return {"ok": False, "path": str(path), "errors": ["artifact_missing"]}
    if path.name != expected_name:
        errors.append("unexpected_artifact_name")
    try:
        signature = signature_loader(path)
    except Exception as exc:
        return {
            "ok": False,
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
            "errors": ["signature_probe_failed"],
            "detail": str(exc)[:1000],
        }
    subject = str(signature.get("signer_subject") or "")
    issuer = str(signature.get("signer_issuer") or "")
    timestamp_subject = str(signature.get("timestamper_subject") or "")
    signer_thumbprint = _normalized_thumbprint(signature.get("signer_thumbprint"))
    usages = signature.get("enhanced_key_usage_oids") or []
    if isinstance(usages, str):
        usages = [usages]
    status = str(signature.get("status") or "")
    signature_type = str(signature.get("signature_type") or "")
    if distribution_mode == "unsigned":
        if status != "NotSigned":
            errors.append("unsigned_release_must_be_authenticode_not_signed")
        if signature_type != "None":
            errors.append("unsigned_release_signature_type_not_none")
        unexpected_identity = {
            "signer_subject": subject,
            "signer_issuer": issuer,
            "signer_thumbprint": signer_thumbprint,
            "signer_not_after": str(signature.get("signer_not_after") or ""),
            "timestamper_subject": timestamp_subject,
            "timestamper_thumbprint": _normalized_thumbprint(signature.get("timestamper_thumbprint")),
            "enhanced_key_usage_oids": [str(value) for value in usages],
        }
        if any(unexpected_identity.values()):
            errors.append("unsigned_release_contains_unexpected_signing_identity")
        return {
            "ok": not errors,
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
            "distribution_mode": distribution_mode,
            "signature": signature,
            "unexpected_identity": unexpected_identity,
            "errors": errors,
        }
    if distribution_mode != "signed":
        errors.append("distribution_mode_invalid")
    if status != "Valid":
        errors.append("authenticode_status_not_valid")
    if signature_type != "Authenticode":
        errors.append("embedded_authenticode_signature_required")
    if not _publisher_matches(expected_publisher, subject):
        errors.append("publisher_mismatch")
    if signer_thumbprint not in allowed_thumbprints:
        errors.append("signer_thumbprint_not_allowlisted")
    if subject and subject.casefold() == issuer.casefold():
        errors.append("self_signed_leaf_rejected")
    if CODE_SIGNING_EKU not in {str(value) for value in usages}:
        errors.append("code_signing_eku_missing")
    if not timestamp_subject:
        errors.append("trusted_timestamp_missing")
    return {
        "ok": not errors,
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "signature": signature,
        "errors": errors,
    }


def verify_pe_identity(
    application: Path,
    package: dict[str, Any],
    loader: Callable[[Path], dict[str, str]] = _powershell_version_info,
) -> dict[str, Any]:
    info = loader(application)
    product = str(package.get("productName") or "")
    version = str(package.get("version") or "")
    errors = []
    for key in ("file_description", "product_name", "internal_name"):
        if info.get(key) != product:
            errors.append(f"pe_{key}_mismatch")
    if not info.get("product_version", "").startswith(version):
        errors.append("pe_product_version_mismatch")
    return {"ok": not errors, "version_info": info, "errors": errors}


def _pe_image_identity(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RuntimeError(f"PE runtime reference is not an MZ executable: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise RuntimeError(f"PE runtime reference has an invalid PE header: {path}")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    table = optional_offset + optional_size
    if section_count <= 0 or section_count > 96 or table + section_count * 40 > len(data):
        raise RuntimeError(f"PE runtime reference has an invalid section table: {path}")
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if optional_magic == 0x20B:
        directory_count_offset = optional_offset + 108
        directories_offset = optional_offset + 112
    elif optional_magic == 0x10B:
        directory_count_offset = optional_offset + 92
        directories_offset = optional_offset + 96
    else:
        raise RuntimeError(f"PE runtime reference has an unsupported optional header: {path}")
    if directory_count_offset + 4 > table:
        raise RuntimeError(f"PE runtime reference has a truncated optional header: {path}")
    directory_count = struct.unpack_from("<I", data, directory_count_offset)[0]
    if directory_count < 3 or directories_offset + directory_count * 8 > table:
        raise RuntimeError(f"PE runtime reference has an invalid data-directory table: {path}")
    resource_directory_offset = directories_offset + 2 * 8
    resource_rva, resource_size = struct.unpack_from("<II", data, resource_directory_offset)

    sections: list[dict[str, Any]] = []
    names: set[str] = set()
    ranges: list[tuple[int, int, str]] = []
    for index in range(section_count):
        offset = table + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="strict")
        virtual_size = struct.unpack_from("<I", data, offset + 8)[0]
        virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
        raw_size = struct.unpack_from("<I", data, offset + 16)[0]
        raw_offset = struct.unpack_from("<I", data, offset + 20)[0]
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if not name or name in names or raw_offset + raw_size > len(data):
            raise RuntimeError(f"PE runtime reference has an invalid section descriptor: {path}")
        names.add(name)
        if raw_size:
            ranges.append((raw_offset, raw_offset + raw_size, name))
        raw = data[raw_offset:raw_offset + raw_size]
        sections.append({
            "name": name,
            "descriptor_offset": offset,
            "descriptor": data[offset:offset + 40],
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
            "characteristics": characteristics,
            "sha256": _bytes_sha256(raw),
        })
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if current[0] < previous[1]:
            raise RuntimeError(f"PE runtime reference has overlapping sections: {path}")
    first_raw_offset = min((start for start, _, _ in ranges), default=len(data))
    final_raw_end = max((end for _, end, _ in ranges), default=first_raw_offset)
    if first_raw_offset < table + section_count * 40 or final_raw_end != len(data):
        raise RuntimeError(f"PE runtime reference has invalid headers or trailing overlay data: {path}")
    resources = [section for section in sections if section["name"] == ".rsrc"]
    if len(resources) != 1:
        raise RuntimeError(f"PE runtime reference must contain exactly one .rsrc section: {path}")
    resource = resources[0]
    if resource_rva != resource["virtual_address"] or resource_size != resource["virtual_size"]:
        raise RuntimeError(f"PE resource directory does not bind the .rsrc section: {path}")
    return {
        "path": str(path),
        "data": data,
        "bytes": len(data),
        "pe_offset": pe_offset,
        "optional_offset": optional_offset,
        "optional_size": optional_size,
        "section_table_offset": table,
        "first_raw_offset": first_raw_offset,
        "resource_directory_offset": resource_directory_offset,
        "resource_directory_rva": resource_rva,
        "resource_directory_size": resource_size,
        "sections": sections,
    }


def _electron_pe_identity(reference_path: Path, application_path: Path) -> dict[str, Any]:
    reference = _pe_image_identity(reference_path)
    application = _pe_image_identity(application_path)
    errors: list[str] = []
    reference_names = [section["name"] for section in reference["sections"]]
    application_names = [section["name"] for section in application["sections"]]
    if reference_names != application_names:
        return {
            "ok": False,
            "section_binding_ok": False,
            "errors": ["electron_pe_section_order_mismatch"],
        }
    if (
        reference["pe_offset"] != application["pe_offset"]
        or reference["optional_offset"] != application["optional_offset"]
        or reference["optional_size"] != application["optional_size"]
        or reference["section_table_offset"] != application["section_table_offset"]
        or reference["first_raw_offset"] != application["first_raw_offset"]
    ):
        errors.append("electron_pe_header_layout_mismatch")

    reference_sections = {section["name"]: section for section in reference["sections"]}
    application_sections = {section["name"]: section for section in application["sections"]}
    reference_resource = reference_sections[".rsrc"]
    application_resource = application_sections[".rsrc"]
    raw_delta = application_resource["raw_size"] - reference_resource["raw_size"]
    if application["bytes"] - reference["bytes"] != raw_delta:
        errors.append("electron_pe_resource_file_delta_mismatch")
    if reference["resource_directory_rva"] != application["resource_directory_rva"]:
        errors.append("electron_pe_resource_rva_mismatch")

    resource_index = reference_names.index(".rsrc")
    section_content: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(reference_names):
        left = reference_sections[name]
        right = application_sections[name]
        left_descriptor = bytearray(left["descriptor"])
        right_descriptor = bytearray(right["descriptor"])
        if name == ".rsrc":
            for relative_offset in (8, 16):
                left_descriptor[relative_offset:relative_offset + 4] = b"\0" * 4
                right_descriptor[relative_offset:relative_offset + 4] = b"\0" * 4
        elif index > resource_index:
            if right["raw_offset"] - left["raw_offset"] != raw_delta:
                errors.append(f"electron_pe_{name}_raw_offset_delta_mismatch")
            left_descriptor[20:24] = b"\0" * 4
            right_descriptor[20:24] = b"\0" * 4
        if left_descriptor != right_descriptor:
            errors.append(f"electron_pe_{name}_descriptor_mismatch")
        content_equal = name == ".rsrc" or left["sha256"] == right["sha256"]
        if not content_equal:
            errors.append(f"electron_pe_{name}_content_mismatch")
        section_content[name] = {
            "reference_sha256": left["sha256"],
            "application_sha256": right["sha256"],
            "content_equal_or_resource": content_equal,
        }

    reference_header = bytearray(reference["data"][:reference["first_raw_offset"]])
    application_header = bytearray(application["data"][:application["first_raw_offset"]])
    for image, header in ((reference, reference_header), (application, application_header)):
        resource_size_offset = image["resource_directory_offset"] + 4
        header[resource_size_offset:resource_size_offset + 4] = b"\0" * 4
        for index, section in enumerate(image["sections"]):
            descriptor_offset = section["descriptor_offset"]
            if section["name"] == ".rsrc":
                header[descriptor_offset + 8:descriptor_offset + 12] = b"\0" * 4
                header[descriptor_offset + 16:descriptor_offset + 20] = b"\0" * 4
            elif index > resource_index:
                header[descriptor_offset + 20:descriptor_offset + 24] = b"\0" * 4
    normalized_header_equal = reference_header == application_header
    if not normalized_header_equal:
        errors.append("electron_pe_execution_header_mismatch")
    return {
        "ok": not errors,
        "section_binding_ok": not errors,
        "normalized_header_equal": normalized_header_equal,
        "reference_normalized_header_sha256": _bytes_sha256(bytes(reference_header)),
        "application_normalized_header_sha256": _bytes_sha256(bytes(application_header)),
        "resource_raw_delta": raw_delta,
        "section_content": section_content,
        "errors": errors,
    }


def _tree_manifest_sha256(files: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_electron_runtime_identity(application: Path, policy: dict[str, Any]) -> dict[str, Any]:
    reference_root = DESKTOP_ROOT / "node_modules" / "electron" / "dist"
    reference_exe = reference_root / "electron.exe"
    expected_exe_hash = str(policy.get("electronReferenceExeSha256") or "")
    expected_tree_hash = str(policy.get("electronReferenceTreeSha256") or "")
    expected_version = str(policy.get("electronVersion") or "")
    reference_files, reference_directories = _tree_snapshot(reference_root)
    reference_tree_hash = _tree_manifest_sha256(reference_files)
    errors = []
    if reference_files.get("electron.exe") != expected_exe_hash:
        errors.append("electron_reference_executable_hash_mismatch")
    if reference_tree_hash != expected_tree_hash:
        errors.append("electron_reference_tree_hash_mismatch")
    if (reference_root / "version").read_text(encoding="utf-8").strip() != expected_version:
        errors.append("electron_reference_version_mismatch")

    application_root = application.parent
    application_files, application_directories = _tree_snapshot(application_root)
    excluded_reference = {"electron.exe", "LICENSE", "resources/default_app.asar", "version"}
    common_runtime = set(reference_files) - excluded_reference
    expected_application_files = common_runtime | {
        APPLICATION_NAME,
        "LICENSE.electron.txt",
        "resources/app.asar",
    }
    missing = sorted(expected_application_files - set(application_files))
    # electron-builder legitimately adds its own NSIS helpers to the packaged tree, so a
    # raw comparison against pristine node_modules/electron/dist flags them as smuggled
    # files and fails a perfectly good build -- the same "reject the genuine article"
    # failure the InstallLocation rule caused. They are permitted, but PINNED BY HASH, so
    # the exemption is a named file with known bytes rather than an open door.
    extra = sorted(
        name for name in set(application_files) - expected_application_files
        if application_files.get(name) != ELECTRON_BUILDER_EXPECTED_EXTRAS.get(name)
    )
    mismatched = sorted(
        name for name in common_runtime
        if name in application_files and application_files[name] != reference_files[name]
    )
    if application_files.get("LICENSE.electron.txt") != reference_files.get("LICENSE"):
        mismatched.append("LICENSE.electron.txt")

    pe_identity = _electron_pe_identity(reference_exe, application)
    section_binding_ok = bool(pe_identity.get("ok"))
    if not section_binding_ok:
        errors.extend(pe_identity.get("errors", ["electron_executable_identity_mismatch"]))
    if missing:
        errors.append("electron_runtime_files_missing")
    if extra:
        errors.append("electron_runtime_files_extra")
    if mismatched:
        errors.append("electron_runtime_files_mismatched")
    return {
        "ok": not errors,
        "reference_root": str(reference_root),
        "reference_executable_sha256": reference_files.get("electron.exe"),
        "reference_tree_sha256": reference_tree_hash,
        "reference_file_count": len(reference_files),
        "reference_directory_count": len(reference_directories),
        "application_file_count": len(application_files),
        "application_directory_count": len(application_directories),
        "pe_identity": pe_identity,
        "section_binding_ok": section_binding_ok,
        "missing": missing,
        "extra": extra,
        "mismatched": sorted(set(mismatched)),
        "errors": errors,
    }


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _windows_process_rows() -> list[dict[str, Any]]:
    script = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,ExecutablePath,CreationDate,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"process-tree probe failed: {(completed.stderr or completed.stdout)[-1000:]}")
    payload = json.loads(completed.stdout or "[]")
    if isinstance(payload, dict):
        payload = [payload]
    return [
        {
            "pid": int(row.get("ProcessId") or 0),
            "parent_pid": int(row.get("ParentProcessId") or 0),
            "executable_path": str(row.get("ExecutablePath") or ""),
            "creation_date": str(row.get("CreationDate") or ""),
            "command_line": str(row.get("CommandLine") or ""),
        }
        for row in payload
        if isinstance(row, dict) and int(row.get("ProcessId") or 0) > 0
    ]


def _process_tree_rows(
    root_pid: int,
    rows: list[dict[str, Any]] | None = None,
) -> dict[int, dict[str, Any]]:
    rows = rows if rows is not None else _windows_process_rows()
    children: dict[int, set[int]] = {}
    by_pid: dict[int, dict[str, Any]] = {}
    for row in rows:
        by_pid[row["pid"]] = row
        children.setdefault(row["parent_pid"], set()).add(row["pid"])
    found = {root_pid} if root_pid in by_pid else set()
    pending = [root_pid]
    while pending:
        parent = pending.pop()
        for child in children.get(parent, set()):
            if child not in found:
                found.add(child)
                pending.append(child)
    return {pid: by_pid[pid] for pid in found if pid in by_pid}


def _process_tree_pids(root_pid: int, rows: list[dict[str, Any]] | None = None) -> set[int]:
    return set(_process_tree_rows(root_pid, rows))


def _port_owner_pids(port: int) -> set[int]:
    script = (
        f"@(Get-NetTCPConnection -State Listen -LocalPort {int(port)} -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty OwningProcess -Unique) | ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"CDP port-owner probe failed: {(completed.stderr or completed.stdout)[-1000:]}")
    payload = json.loads(completed.stdout or "[]")
    if isinstance(payload, int):
        payload = [payload]
    return {int(value) for value in payload if int(value) > 0}


def _same_process_identity(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    expected_created = str(expected.get("creation_date") or "")
    actual_created = str(actual.get("creation_date") or "")
    expected_exe = os.path.normcase(os.path.normpath(str(expected.get("executable_path") or "")))
    actual_exe = os.path.normcase(os.path.normpath(str(actual.get("executable_path") or "")))
    return (
        bool(expected_created)
        and bool(actual_created)
        and bool(expected_exe)
        and bool(actual_exe)
        and expected_created == actual_created
        and expected_exe == actual_exe
    )


def _stop_audit_process(
    process: subprocess.Popen[Any],
    observed_rows: dict[int, dict[str, Any]] | None = None,
    port_owner_pids: set[int] | None = None,
    audit_port: int | None = None,
) -> dict[str, Any]:
    if os.name == "nt":
        observed = dict(observed_rows or {})
        current_rows = _windows_process_rows()
        current_by_pid = {row["pid"]: row for row in current_rows}
        observed.update(_process_tree_rows(process.pid, current_rows))
        for pid in port_owner_pids or set():
            if pid in current_by_pid:
                observed.setdefault(pid, current_by_pid[pid])
        before = sorted(observed)
        kill_results = []
        targets = before or [process.pid]
        for pid in reversed(targets):
            current = {row["pid"]: row for row in _windows_process_rows()}.get(pid)
            expected = observed.get(pid)
            if expected and (not current or not _same_process_identity(expected, current)):
                kill_results.append({"pid": pid, "returncode": None, "skipped": "identity_changed_or_exited"})
                continue
            completed = subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            kill_results.append({"pid": pid, "returncode": completed.returncode})
        deadline = time.monotonic() + 15
        remaining: list[int] = []
        remaining_port_owners: list[int] = []
        while time.monotonic() < deadline:
            current_by_pid = {row["pid"]: row for row in _windows_process_rows()}
            remaining = sorted(
                pid for pid, expected in observed.items()
                if pid in current_by_pid and _same_process_identity(expected, current_by_pid[pid])
            )
            remaining_port_owners = sorted(_port_owner_pids(audit_port)) if audit_port else []
            if not remaining and not remaining_port_owners:
                break
            time.sleep(0.25)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        return {
            "ok": not remaining and not remaining_port_owners,
            "method": "tracked_lineage_and_taskkill_identity_bound",
            "root_pid": process.pid,
            "observed_tree_pids": before,
            "kill_results": kill_results,
            "remaining_tree_pids": remaining,
            "remaining_port_owner_pids": remaining_port_owners,
        }
    if process.poll() is not None:
        return {"ok": True, "method": "already_exited", "returncode": process.returncode}
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    return {"ok": process.poll() is not None, "method": "terminate_audit_process"}


def _recv_exact(stream: Any, count: int) -> bytes:
    value = bytearray()
    while len(value) < count:
        chunk = stream.read(count - len(value))
        if not chunk:
            raise RuntimeError("CDP WebSocket closed before a complete frame arrived")
        value.extend(chunk)
    return bytes(value)


def _cdp_command(websocket_url: str, message: dict[str, Any], timeout_seconds: int = 5) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(websocket_url)
    if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.port:
        raise RuntimeError("CDP target did not expose a loopback WebSocket URL")
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    with socket.create_connection((parsed.hostname, parsed.port), timeout=timeout_seconds) as client:
        client.settimeout(timeout_seconds)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        client.sendall(request)
        stream = client.makefile("rb")
        status = stream.readline().decode("latin-1").strip()
        headers: dict[str, str] = {}
        while True:
            line = stream.readline().decode("latin-1")
            if line in {"\r\n", "\n", ""}:
                break
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        expected_accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if " 101 " not in f" {status} " or headers.get("sec-websocket-accept") != expected_accept:
            raise RuntimeError("CDP WebSocket handshake was not valid")
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        mask = os.urandom(4)
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        client.sendall(bytes(header) + masked)
        while True:
            first, second = _recv_exact(stream, 2)
            opcode = first & 0x0F
            frame_length = second & 0x7F
            if frame_length == 126:
                frame_length = struct.unpack("!H", _recv_exact(stream, 2))[0]
            elif frame_length == 127:
                frame_length = struct.unpack("!Q", _recv_exact(stream, 8))[0]
            mask_key = _recv_exact(stream, 4) if second & 0x80 else b""
            frame = _recv_exact(stream, frame_length)
            if mask_key:
                frame = bytes(value ^ mask_key[index % 4] for index, value in enumerate(frame))
            if opcode == 0x9:
                continue
            if opcode != 0x1:
                raise RuntimeError(f"unexpected CDP WebSocket opcode: {opcode}")
            response = json.loads(frame.decode("utf-8"))
            if response.get("id") == message.get("id"):
                if response.get("error"):
                    raise RuntimeError(f"CDP command failed: {response['error']}")
                return response


def _install_windows_kill_on_close_job() -> tuple[Any, Any]:
    if os.name != "nt":
        raise RuntimeError("Windows Job Object containment is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise ctypes.WinError(error)
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise ctypes.WinError(error)
    return job, kernel32


def _audit_job_wrapper_main(arguments: list[str]) -> int:
    if len(arguments) != 5:
        raise RuntimeError("audit job wrapper requires application, port, profile, handshake, and nonce")
    application, raw_port, profile, raw_handshake, nonce = arguments
    job, kernel32 = _install_windows_kill_on_close_job()
    child: subprocess.Popen[Any] | None = None
    try:
        child = subprocess.Popen(
            [
                application,
                f"--remote-debugging-port={int(raw_port)}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--disable-gpu",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        handshake = Path(raw_handshake)
        temporary = handshake.with_suffix(handshake.suffix + ".tmp")
        temporary.write_text(json.dumps({
            "application_pid": child.pid,
            "containment": "windows_job_object_kill_on_close",
            "wrapper_pid": os.getpid(),
            # The launch NONCE, not a pid, is what proves this handshake came from the
            # process the caller spawned. sys.executable can be a venv launcher shim that
            # re-execs the real interpreter as a CHILD, so os.getpid() here legitimately
            # differs from the pid the caller is holding -- which made a correct launch
            # look like an identity mismatch.
            "nonce": nonce,
        }), encoding="utf-8")
        os.replace(temporary, handshake)
        return int(child.wait())
    finally:
        kernel32.CloseHandle(job)


def _launch_audit_application(
    application: Path,
    port: int,
    profile: str,
    handshake_path: Path,
) -> tuple[subprocess.Popen[Any], int, str]:
    if os.name != "nt":
        process = subprocess.Popen(
            [str(application), f"--remote-debugging-port={port}", f"--user-data-dir={profile}", "--no-first-run", "--disable-gpu"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        return process, process.pid, "direct_process"
    nonce = secrets.token_hex(16)
    wrapper = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--audit-job-wrapper", str(application), str(port), profile, str(handshake_path), nonce],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if handshake_path.is_file():
            payload = json.loads(handshake_path.read_text(encoding="utf-8"))
            if payload.get("nonce") != nonce or payload.get("containment") != "windows_job_object_kill_on_close":
                raise RuntimeError("audit job wrapper handshake identity mismatch")
            return wrapper, int(payload["application_pid"]), str(payload["containment"])
        if wrapper.poll() is not None:
            raise RuntimeError(f"audit job wrapper exited before handshake ({wrapper.returncode})")
        time.sleep(0.1)
    wrapper.kill()
    wrapper.wait(timeout=10)
    raise RuntimeError("audit job wrapper did not prove containment within 20 seconds")


def _wait_for_released_file(path: Path, timeout_seconds: float = 20.0) -> bool:
    """Wait until `path` can be opened for exclusive write, i.e. nobody still maps it.

    Read access is not a sufficient test on Windows: a memory-mapped executable image is
    still readable while it cannot be replaced or deleted, which is exactly the operation
    that fails afterwards. Opening 'r+b' is the closest cheap proxy for "the mapping is
    gone". Returns False on timeout rather than raising, so the caller reports a real
    lock instead of an exception from a cleanup path.
    """
    if not path.exists():
        return True
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with path.open("r+b"):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def audit_electron_ui(application: Path, policy: dict[str, Any], timeout_seconds: int = 45) -> dict[str, Any]:
    expected_title = str(policy.get("expectedWindowTitle") or "")
    expected_suffix = str(policy.get("requiredUiUrlSuffix") or "").replace("\\", "/")
    if not expected_title or not expected_suffix.startswith("/"):
        raise RuntimeError("release policy requires expectedWindowTitle and requiredUiUrlSuffix")
    port = _free_local_port()
    # ignore_cleanup_errors: Chromium holds its profile `lockfile` open briefly after the
    # process is signalled, so deleting this scratch profile can raise WinError 32 and
    # fail an audit that actually succeeded. Nothing is verified from this directory; it
    # exists only to keep the audited launch out of the real user profile.
    with tempfile.TemporaryDirectory(
        prefix="skynet-desktop-ui-audit-", ignore_cleanup_errors=True
    ) as raw_profile:
        handshake_path = Path(raw_profile) / "audit_job_handshake.json"
        process, application_pid, containment = _launch_audit_application(
            application, port, raw_profile, handshake_path
        )
        target: dict[str, Any] | None = None
        runtime_value: dict[str, Any] | None = None
        port_owners: set[int] = set()
        process_tree: set[int] = set()
        observed_rows: dict[int, dict[str, Any]] = {}
        port_owner_executables: dict[int, str] = {}
        lineage_identity_complete = False
        error = ""
        deadline = time.monotonic() + timeout_seconds
        try:
            while time.monotonic() < deadline:
                if os.name == "nt":
                    rows = _windows_process_rows()
                    snapshot = _process_tree_rows(process.pid, rows)
                    observed_rows.update(snapshot)
                    process_tree = set(snapshot)
                    lineage_identity_complete = bool(snapshot) and all(
                        row.get("creation_date") and row.get("executable_path")
                        for row in snapshot.values()
                    )
                if process.poll() is not None:
                    error = f"Electron audit process exited early ({process.returncode})"
                    break
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                    for row in payload if isinstance(payload, list) else []:
                        title = str(row.get("title") or "")
                        url = str(row.get("url") or "").replace("\\", "/")
                        if (
                            row.get("type") == "page"
                            and title == expected_title
                            and url.endswith(expected_suffix)
                            and str(row.get("webSocketDebuggerUrl") or "").startswith("ws://")
                        ):
                            response = _cdp_command(
                                str(row["webSocketDebuggerUrl"]),
                                {
                                    "id": 1,
                                    "method": "Runtime.evaluate",
                                    "params": {
                                        "expression": "({title:document.title,userAgent:navigator.userAgent,app:!!document.querySelector('#app'),input:!!document.querySelector('#input'),orchestration:!!document.querySelector('#orchestrationToggle')})",
                                        "returnByValue": True,
                                    },
                                },
                            )
                            value = response.get("result", {}).get("result", {}).get("value")
                            port_owners = _port_owner_pids(port) if os.name == "nt" else {process.pid}
                            if os.name == "nt":
                                current_by_pid = {item["pid"]: item for item in _windows_process_rows()}
                                for pid in port_owners:
                                    if pid in current_by_pid:
                                        observed_rows.setdefault(pid, current_by_pid[pid])
                                        port_owner_executables[pid] = current_by_pid[pid]["executable_path"]
                            expected_executable = os.path.normcase(os.path.normpath(str(application.resolve())))
                            owners_are_application = all(
                                os.path.normcase(os.path.normpath(value)) == expected_executable
                                for value in port_owner_executables.values()
                            ) if os.name == "nt" else True
                            if (
                                isinstance(value, dict)
                                and value.get("title") == expected_title
                                and "Electron/" in str(value.get("userAgent") or "")
                                and value.get("app") is True
                                and value.get("input") is True
                                and value.get("orchestration") is True
                                and port_owners
                                and port_owners <= process_tree
                                and len(port_owner_executables) == len(port_owners)
                                and owners_are_application
                                and lineage_identity_complete
                                and containment == "windows_job_object_kill_on_close"
                            ):
                                target = row
                                runtime_value = value
                                break
                    if target and runtime_value:
                        break
                except Exception as exc:
                    error = str(exc)[:500]
                time.sleep(0.25)
        finally:
            cleanup = _stop_audit_process(process, observed_rows, port_owners, port)
            # Electron MEMORY-MAPS resources/app.asar, and Windows does not drop the
            # mapping the instant the process is signalled. Whatever reads or removes the
            # installed tree next then hits WinError 32 and the whole audit fails on a
            # race rather than on a defect. Wait, bounded, for the mapping to clear.
            cleanup["asar_unlocked"] = _wait_for_released_file(
                application.parent / "resources" / "app.asar"
            )
    return {
        "ok": target is not None and cleanup.get("ok") is True,
        "pid": application_pid,
        "wrapper_pid": process.pid,
        "containment": containment,
        "cdp_port": port,
        "target": {
            "type": target.get("type"),
            "title": target.get("title"),
            "url": target.get("url"),
        } if target else None,
        "runtime_evaluation": runtime_value,
        "port_owner_pids": sorted(port_owners),
        "port_owner_executables": {str(pid): value for pid, value in sorted(port_owner_executables.items())},
        "audit_process_tree_pids": sorted(process_tree),
        "observed_lineage_pids": sorted(observed_rows),
        "lineage_identity_complete": lineage_identity_complete,
        "cleanup": cleanup,
        "error": "" if target else error or "expected Electron page target was not observed",
    }


def _powershell_shell_state(shortcut_name: str) -> dict[str, Any]:
    script = r"""
$ErrorActionPreference = 'Stop'
$name = $env:SKYNET_DESKTOP_SHORTCUT_NAME
$roots = [ordered]@{
  user_desktop = [Environment]::GetFolderPath('Desktop')
  common_desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
  user_programs = [Environment]::GetFolderPath('Programs')
  common_programs = [Environment]::GetFolderPath('CommonPrograms')
}
$shell = New-Object -ComObject WScript.Shell
$shortcuts = @()
foreach ($kind in $roots.Keys) {
  $shortcutRoot = [string]$roots[$kind]
  if (-not (Test-Path -LiteralPath $shortcutRoot)) { continue }
  foreach ($candidate in @(
    Get-ChildItem -LiteralPath $shortcutRoot -Filter ($name + '.lnk') `
      -File -Recurse -Force -ErrorAction SilentlyContinue
  )) {
    $link = $shell.CreateShortcut($candidate)
    $shortcuts += [ordered]@{
      kind = $kind
      path = [string]$candidate.FullName
      target = [string]$link.TargetPath
      arguments = [string]$link.Arguments
    }
  }
}
$uninstall = @()
foreach ($root in @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)) {
  if (-not (Test-Path -LiteralPath $root)) { continue }
  foreach ($key in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
    $row = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
    if ($null -ne $row -and [string]$row.DisplayName -like ($name + '*')) {
      $uninstall += [ordered]@{
        key = [string]$key.Name
        display_name = [string]$row.DisplayName
        install_location = [string]$row.InstallLocation
        uninstall_string = [string]$row.UninstallString
        quiet_uninstall_string = [string]$row.QuietUninstallString
      }
    }
  }
}
$startApps = @(
  Get-StartApps -ErrorAction SilentlyContinue |
    Where-Object { [string]$_.Name -eq $name } |
    ForEach-Object { [ordered]@{ name = [string]$_.Name; app_id = [string]$_.AppID } }
)
[ordered]@{
  shortcuts = @($shortcuts)
  uninstall_entries = @($uninstall)
  start_apps = @($startApps)
} | ConvertTo-Json -Compress -Depth 6
"""
    env = os.environ.copy()
    env["SKYNET_DESKTOP_SHORTCUT_NAME"] = shortcut_name
    completed = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
        env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Windows shell-state probe failed: {(completed.stderr or completed.stdout)[-1000:]}")
    payload = json.loads(completed.stdout or "{}")
    if not isinstance(payload, dict):
        raise RuntimeError("Windows shell-state probe returned a non-object")
    for key in ("shortcuts", "uninstall_entries", "start_apps"):
        if not isinstance(payload.get(key), list):
            payload[key] = []
    return payload


def _norm_windows_path(value: object) -> str:
    return os.path.normcase(os.path.normpath(str(value or "").strip().strip('"')))


def _windows_command_parts(value: object) -> tuple[str, str]:
    command = str(value or "").strip()
    if not command:
        return "", ""
    if command.startswith('"'):
        end = command.find('"', 1)
        return (command[1:end], command[end + 1:].strip()) if end > 1 else ("", "")
    match = re.match(r"(?i)(.+?\.exe)(?:\s|$)", command)
    if not match:
        return "", ""
    return match.group(1), command[match.end(1):].strip()


def _windows_command_executable(value: object) -> str:
    return _windows_command_parts(value)[0]


def _same_or_descendant_path(value: object, root: object) -> bool:
    candidate = _norm_windows_path(value)
    boundary = _norm_windows_path(root)
    return bool(candidate and boundary) and (
        candidate == boundary or candidate.startswith(boundary.rstrip("\\/") + os.sep)
    )


def _installed_shell_checks(
    state: dict[str, Any],
    application: Path,
    install_root: Path,
    shortcut_name: str,
    expected_app_id: str,
) -> dict[str, Any]:
    target = _norm_windows_path(application.resolve())
    root = _norm_windows_path(install_root.resolve())
    shortcuts = state.get("shortcuts", [])
    start_shortcuts = [row for row in shortcuts if row.get("kind") in {"user_programs", "common_programs"}]
    desktop_shortcuts = [row for row in shortcuts if row.get("kind") in {"user_desktop", "common_desktop"}]
    exact_start = [
        row for row in start_shortcuts
        if _norm_windows_path(row.get("target")) == target
        and not str(row.get("arguments") or "").strip()
    ]
    exact_desktop = [
        row for row in desktop_shortcuts
        if _norm_windows_path(row.get("target")) == target
        and not str(row.get("arguments") or "").strip()
    ]
    exact_start_apps = [
        row for row in state.get("start_apps", [])
        if str(row.get("name") or "") == shortcut_name
        and str(row.get("app_id") or "") == expected_app_id
    ]
    uninstall_entries = state.get("uninstall_entries", [])
    on_disk_uninstallers = sorted(install_root.glob("Uninstall*.exe"))
    exact_uninstaller = on_disk_uninstallers[0] if len(on_disk_uninstallers) == 1 else None
    bound_uninstall = []
    if exact_uninstaller is not None:
        expected_uninstaller = _norm_windows_path(exact_uninstaller.resolve())
        for row in uninstall_entries:
            uninstall_exe, uninstall_args = _windows_command_parts(row.get("uninstall_string"))
            quiet_exe, quiet_args = _windows_command_parts(row.get("quiet_uninstall_string"))
            # NSIS leaves InstallLocation empty (proven live), so bind on the uninstaller
            # path -- which is what actually gets executed -- and only cross-check the
            # advisory location when the installer set it.
            declared_location = str(row.get("install_location") or "").strip()
            if (
                (not declared_location or _norm_windows_path(declared_location) == root)
                and _norm_windows_path(uninstall_exe) == expected_uninstaller
                and uninstall_args.casefold() == "/currentuser"
                and _norm_windows_path(quiet_exe) == expected_uninstaller
                and quiet_args.casefold() == "/currentuser /s"
            ):
                bound_uninstall.append({
                    **row,
                    "parsed_uninstall_command": [uninstall_exe, "/currentuser"],
                    "parsed_quiet_uninstall_command": [quiet_exe, "/currentuser", "/S"],
                })
    errors = []
    if len(start_shortcuts) != 1 or len(exact_start) != 1:
        errors.append("start_menu_shortcut_missing_or_ambiguous")
    if len(desktop_shortcuts) != 1 or len(exact_desktop) != 1:
        errors.append("desktop_shortcut_missing_or_ambiguous")
    if len(exact_start_apps) != 1 or len(state.get("start_apps", [])) != 1:
        errors.append("windows_start_app_catalog_missing_unbound_or_ambiguous")
    if exact_uninstaller is None:
        errors.append("on_disk_uninstaller_missing_or_ambiguous")
    if len(uninstall_entries) != 1 or len(bound_uninstall) != 1:
        errors.append("uninstall_registry_entry_missing_invalid_or_ambiguous")
    return {
        "ok": not errors,
        "errors": errors,
        "exact_start_menu_shortcuts": exact_start,
        "exact_desktop_shortcuts": exact_desktop,
        "exact_start_apps": exact_start_apps,
        "exact_on_disk_uninstaller": str(exact_uninstaller) if exact_uninstaller else "",
        "bound_uninstall_entries": bound_uninstall,
        "raw": state,
    }


def _audited_quiet_uninstall_commands(
    shell_state: dict[str, Any], install_root: Path
) -> list[list[str]]:
    """Quiet uninstall commands registered against THIS audited install root.

    Read from the live registry rather than from a successful ``_installed_shell_checks``
    result, because cleanup must also work on the failure path, where shell verification
    never ran and ``bound_uninstall_entries`` therefore does not exist.

    A registry row is UNTRUSTED input. ``install_location`` is whatever the row claims,
    so matching on it alone would let a row name the audited root while pointing
    ``QuietUninstallString`` at an unrelated executable with arbitrary arguments, and the
    gate would then execute it. Every command returned here must therefore satisfy all
    of: the executable resolves to a real file INSIDE the audited root, it is that root's
    single ``Uninstall*.exe``, and the arguments are exactly ``/currentuser /S``.
    """
    # The ROOT is as untrusted as the executable. Resolving a linked or junctioned root
    # succeeds and every later descendant check then passes relative to wherever that
    # link pointed, which re-opens the escape one level up. Refuse a root that is not a
    # real directory reached without traversing a reparse point.
    try:
        root_metadata = os.lstat(install_root)
        if install_root.is_symlink() or bool(getattr(install_root, "is_junction", lambda: False)()):
            return []
        if _metadata_has_windows_reparse_point(root_metadata, install_root):
            return []
        if not stat.S_ISDIR(root_metadata.st_mode):
            return []
        root_path = install_root.resolve(strict=True)
        if _norm_windows_path(root_path) != _norm_windows_path(install_root.absolute()):
            return []
    except (OSError, RuntimeError):
        return []
    root = _norm_windows_path(root_path)
    on_disk = sorted(root_path.glob("Uninstall*.exe")) if root_path.is_dir() else []
    if len(on_disk) != 1:
        return []
    candidate = on_disk[0]
    # resolve() FOLLOWS links, so comparing the registry value against the resolved path
    # is not containment: a reparse point named Uninstall*.exe inside the audited root
    # resolves to a binary OUTSIDE it, and the comparison then happily matches. Require
    # the entry itself to be a regular, non-reparse file AND its resolved path to be a
    # descendant of the resolved root before it can ever become a command.
    try:
        metadata = os.lstat(candidate)
        if candidate.is_symlink() or bool(getattr(candidate, "is_junction", lambda: False)()):
            return []
        if _metadata_has_windows_reparse_point(metadata, candidate):
            return []
        if not stat.S_ISREG(metadata.st_mode):
            return []
        # A HARD LINK defeats every check above: it carries no reparse point, lstat calls
        # it a regular file, and resolve() returns the in-root path itself -- while the
        # bytes are an external file's. Reparse checks cannot see it because there is no
        # reparse point; only the link count betrays it. An installer-written uninstaller
        # has exactly one name.
        if getattr(metadata, "st_nlink", 1) != 1:
            return []
        resolved_exe = candidate.resolve(strict=True)
        resolved_exe.relative_to(root_path)
    except (OSError, ValueError, RuntimeError):
        return []
    expected_exe = _norm_windows_path(resolved_exe)
    commands: list[list[str]] = []
    for row in shell_state.get("uninstall_entries", []):
        quiet_exe, quiet_args = _windows_command_parts(row.get("quiet_uninstall_string"))
        if not quiet_exe:
            continue
        # InstallLocation is ADVISORY and the real NSIS installer leaves it EMPTY --
        # proven live, not assumed. Requiring it to equal the root rejected the genuine
        # uninstaller, which then also starved the cleanup sweep and leaked shortcuts and
        # a registry key that could never remove themselves. Containment is enforced on
        # the executable actually run, below; this field only has to be consistent when
        # the installer bothered to set it.
        declared_location = str(row.get("install_location") or "").strip()
        if declared_location and _norm_windows_path(declared_location) != root:
            continue
        if _norm_windows_path(quiet_exe) != expected_exe:
            continue
        # String comparison case-folds, and an NTFS directory can be case-sensitive, so
        # two DISTINCT files differing only in case would compare equal. Settle identity
        # on the filesystem instead: samefile compares the volume and file index, which
        # no amount of casing can spoof.
        try:
            if not os.path.samefile(quiet_exe, candidate):
                continue
        except OSError:
            continue
        arguments = quiet_args.split()
        if [value.casefold() for value in arguments] != ["/currentuser", "/s"]:
            continue
        commands.append([quiet_exe, *arguments])
    return commands


def _safely_contained_executable(candidate: Path, root_path: Path) -> bool:
    """True only when `candidate` is a real file safely inside `root_path`.

    This is the SAFETY floor shared by validation and cleanup: no symlink, no junction,
    no reparse point, no hard link, a regular file, and a strict resolution that stays
    inside the strictly resolved root. It says nothing about arguments or registered
    form, which are correctness concerns rather than safety ones.
    """
    try:
        metadata = os.lstat(candidate)
        if candidate.is_symlink() or bool(getattr(candidate, "is_junction", lambda: False)()):
            return False
        if _metadata_has_windows_reparse_point(metadata, candidate):
            return False
        if not stat.S_ISREG(metadata.st_mode):
            return False
        if getattr(metadata, "st_nlink", 1) != 1:
            return False
        candidate.resolve(strict=True).relative_to(root_path)
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _containment_only_uninstall_commands(
    shell_state: dict[str, Any], install_root: Path
) -> list[list[str]]:
    """Removal commands that satisfy CONTAINMENT only, for the cleanup path.

    Deliberately does not require the exact `/currentuser /S` form, an exact registered
    entry, or a matching InstallLocation. A machine left dirty because the registry row
    was merely non-canonical is a worse outcome than running a contained uninstaller with
    the arguments the installer itself registered.
    """
    try:
        root_path = install_root.resolve(strict=True)
    except OSError:
        return []
    commands: list[list[str]] = []
    seen: set[str] = set()
    for row in shell_state.get("uninstall_entries", []):
        for value in (row.get("quiet_uninstall_string"), row.get("uninstall_string")):
            exe, args = _windows_command_parts(value)
            if not exe:
                continue
            candidate = Path(exe)
            if not _safely_contained_executable(candidate, root_path):
                continue
            key = _norm_windows_path(exe)
            if key in seen:
                continue
            seen.add(key)
            arguments = args.split() or ["/S"]
            if "/S" not in [part.upper() for part in arguments]:
                arguments.append("/S")
            commands.append([exe, *arguments])
            break
    return commands


def _best_effort_uninstall(install_root: Path, shortcut_name: str) -> dict[str, Any]:
    """Remove installer-created shell state while a failure is already propagating.

    This runs from a ``finally`` during exception unwind, so it must NEVER raise: the
    original failure is the truth the caller needs, and masking it with a cleanup error
    would hide why the audit failed. Everything it could not remove is recorded as
    ``residue`` so a leak is visible instead of silent.
    """
    record: dict[str, Any] = {
        "reason": "installer_ran_then_audit_failed",
        "attempted_commands": [],
        "returncodes": [],
        "errors": [],
    }
    # One outer guard around EVERYTHING. Command derivation, iteration and the residue
    # probe are all inside it: an exception escaping any of them would replace the
    # original audit failure with a cleanup error, which is the specific way this
    # function could lie about why the audit failed.
    try:
        try:
            shell_state = _powershell_shell_state(shortcut_name)
        except Exception as exc:
            record["errors"].append(f"shell_state_probe_failed:{type(exc).__name__}:{exc}")
            record["clean"] = False
            return record
        try:
            commands = _audited_quiet_uninstall_commands(shell_state, install_root)
            record["strict_commands"] = len(commands)
            if not commands:
                # CLEANUP MUST NOT DEPEND ON THE STRICT PASS CRITERIA. Proven live: the
                # real NSIS row leaves InstallLocation empty, the strict derivation
                # returned nothing, and the sweep therefore removed nothing while the
                # audit had already created shortcuts and a registry key. Validation and
                # removal are different jobs: to PASS we demand exact arguments and an
                # exact registered form; to REMOVE we only need an executable that is
                # safely contained in the audited root.
                commands = _containment_only_uninstall_commands(shell_state, install_root)
                record["fallback_commands"] = len(commands)
        except Exception as exc:
            record["errors"].append(f"command_derivation_failed:{type(exc).__name__}:{exc}")
            record["clean"] = False
            return record
        for command in commands:
            record["attempted_commands"].append(command)
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=240,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                record["returncodes"].append(completed.returncode)
            except Exception as exc:
                record["errors"].append(f"uninstall_failed:{type(exc).__name__}:{exc}")
        try:
            residual = _powershell_shell_state(shortcut_name)
            record["residue"] = {
                "shortcuts": residual["shortcuts"],
                "uninstall_entries": residual["uninstall_entries"],
                "start_apps": residual["start_apps"],
            }
            record["clean"] = not (
                residual["shortcuts"] or residual["uninstall_entries"] or residual["start_apps"]
            )
        except Exception as exc:
            record["errors"].append(f"residue_probe_failed:{type(exc).__name__}:{exc}")
            record["clean"] = False
        return record
    except BaseException as exc:  # noqa: BLE001 - a cleanup error must never win
        record["errors"].append(f"cleanup_aborted:{type(exc).__name__}:{exc}")
        record["clean"] = False
        return record


@contextlib.contextmanager
def installed_nsis_payload(installer: Path, policy: dict[str, Any]) -> Iterator[dict[str, Any]]:
    # ignore_cleanup_errors: Electron keeps resources/app.asar memory-mapped for a moment
    # after exit, so deleting this directory can raise WinError 32 and sink an otherwise
    # passing audit on a race. Removal is not taken on trust because of this -- the
    # uninstall verification below independently asserts the install root, both shortcuts,
    # the registry entry and the Start Apps entry are gone. This only stops a temp-dir
    # cleanup race from masquerading as an audit failure.
    with tempfile.TemporaryDirectory(
        prefix="skynet-desktop-install-audit-", ignore_cleanup_errors=True
    ) as raw_temp:
        install_root = Path(raw_temp) / "installed"
        shortcut_name = str(policy.get("shortcutName") or "")
        expected_app_id = str(policy.get("appUserModelId") or "")
        if not shortcut_name or not expected_app_id:
            raise RuntimeError("release policy requires shortcutName and appUserModelId")
        baseline = _powershell_shell_state(shortcut_name)
        if baseline["shortcuts"] or baseline["uninstall_entries"] or baseline["start_apps"]:
            raise RuntimeError("pre-existing Skynet Desktop shell state would make the isolated audit destructive")
        # The cleanup guard is armed BEFORE the installer is launched, not after it
        # returns. subprocess.run itself can raise -- TimeoutExpired most obviously --
        # and a timed-out installer may already have written shortcuts, a Start Apps
        # entry and an uninstall registry key. Arming after the call left that case
        # with only TemporaryDirectory cleanup, which removes files and no shell state.
        state: dict[str, Any] = {"root": install_root}
        try:
            completed = subprocess.run(
                [str(installer), "/S", f"/D={install_root}"],
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            state["installer_returncode"] = completed.returncode
            if completed.returncode != 0:
                raise RuntimeError(f"silent NSIS install failed ({completed.returncode})")
            application = install_root / APPLICATION_NAME
            if not application.is_file():
                raise RuntimeError("silent NSIS install did not produce Skynet Desktop.exe")
            install_shell: dict[str, Any] = {}
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                install_shell = _installed_shell_checks(
                    _powershell_shell_state(shortcut_name),
                    application,
                    install_root,
                    shortcut_name,
                    expected_app_id,
                )
                if install_shell.get("ok"):
                    break
                time.sleep(0.5)
            if not install_shell.get("ok"):
                raise RuntimeError(f"installed Windows shell integration failed: {install_shell.get('errors')}")
            state["application"] = application
            state["install_shell"] = install_shell
            yield state
        finally:
            if sys.exc_info()[0] is not None:
                # A failure is already propagating. Clean up what the installer created
                # and let the ORIGINAL exception surface; a cleanup error here would
                # replace the real diagnosis with a misleading one.
                state["failure_cleanup"] = _best_effort_uninstall(install_root, shortcut_name)
            else:
                # The strict teardown can itself fail: the uninstaller can time out or
                # return nonzero, a shell probe can raise, or state can survive the
                # uninstall. Every one of those leaves installer-created shortcuts and
                # registry entries on the machine, so the best-effort sweep has to run
                # there too -- and its record must not replace the strict failure, which
                # is the one the caller needs to see.
                try:
                    _strict_uninstall_verification(state, install_root, shortcut_name)
                except BaseException:
                    state["failure_cleanup"] = _best_effort_uninstall(install_root, shortcut_name)
                    raise


def _remove_residual_audit_shortcuts(install_root: Path, shortcut_name: str) -> list[str]:
    """Delete leftover shortcuts that point INSIDE the audited install root.

    Observed live: the NSIS uninstaller removed the registry entry and the Start Apps
    entry but left the Desktop .lnk behind, still targeting the audit's temporary install
    directory. The audit then correctly reported failure and correctly left the machine
    dirty, which is the wrong end state for a tool that installs things on purpose.

    Containment is what makes this safe to automate: a shortcut is only removed when its
    resolved target lives inside the audited root, which is a throwaway temp directory
    this process created. A user's real Skynet Desktop shortcut points at their install
    and is therefore never touched.
    """
    removed: list[str] = []
    try:
        root = _norm_windows_path(install_root.resolve())
    except OSError:
        return removed
    try:
        state = _powershell_shell_state(shortcut_name)
    except Exception:
        return removed
    for row in state.get("shortcuts", []):
        target = _norm_windows_path(row.get("target"))
        path = str(row.get("path") or "")
        if not path or not target.startswith(root):
            continue
        try:
            Path(path).unlink()
            removed.append(path)
        except OSError:
            continue
    return removed


def _strict_uninstall_verification(
    state: dict[str, Any], install_root: Path, shortcut_name: str
) -> None:
    """Success-path teardown: the uninstall must run and must remove every trace."""
    bound_entries = state.get("install_shell", {}).get("bound_uninstall_entries", [])
    if len(bound_entries) != 1:
        raise RuntimeError("audited NSIS installation did not expose one exact registered uninstaller")
    registered_quiet_command = bound_entries[0].get("parsed_quiet_uninstall_command")
    if not isinstance(registered_quiet_command, list) or len(registered_quiet_command) != 3:
        raise RuntimeError("registered quiet uninstall command was not captured exactly")
    # `_installed_shell_checks` derives that command WITHOUT the containment hardening, so
    # trusting it here would let the success path execute an external uninstaller that the
    # failure path would have refused. Re-derive through the hardened function and require
    # the two to agree; anything else is a containment bypass by another route.
    contained = _audited_quiet_uninstall_commands(
        _powershell_shell_state(shortcut_name), install_root
    )
    normalized = [
        [_norm_windows_path(command[0]), *[part.casefold() for part in command[1:]]]
        for command in contained
    ]
    requested = [
        _norm_windows_path(registered_quiet_command[0]),
        *[str(part).casefold() for part in registered_quiet_command[1:]],
    ]
    if requested not in normalized:
        raise RuntimeError(
            "registered quiet uninstall command is not contained within the audited install root"
        )
    uninstall = subprocess.run(
        [str(value) for value in registered_quiet_command],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    state["uninstaller_returncode"] = uninstall.returncode
    if uninstall.returncode != 0:
        raise RuntimeError(f"silent NSIS uninstall failed ({uninstall.returncode})")
    uninstall_state: dict[str, Any] = {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        shell_state = _powershell_shell_state(shortcut_name)
        uninstall_state = {
            "install_root_removed": not install_root.exists(),
            "shortcuts_removed": not shell_state["shortcuts"],
            "uninstall_registry_removed": not shell_state["uninstall_entries"],
            "start_app_catalog_removed": not shell_state["start_apps"],
            "shell_state": shell_state,
        }
        uninstall_state["ok"] = all(
            value for key, value in uninstall_state.items()
            if key != "shell_state"
        )
        if uninstall_state["ok"]:
            break
        time.sleep(0.5)
    if not uninstall_state.get("ok"):
        # The uninstaller can leave a shortcut behind even when it removed the registry
        # entry and the catalog entry. Sweep only what points into the audited root, then
        # re-verify: a genuine failure still fails, but the machine is not left dirty by
        # a tool whose whole purpose is to install and remove cleanly.
        residual = _remove_residual_audit_shortcuts(install_root, shortcut_name)
        if residual:
            state["residual_shortcuts_removed"] = residual
            shell_state = _powershell_shell_state(shortcut_name)
            uninstall_state = {
                "install_root_removed": not install_root.exists(),
                "shortcuts_removed": not shell_state["shortcuts"],
                "uninstall_registry_removed": not shell_state["uninstall_entries"],
                "start_app_catalog_removed": not shell_state["start_apps"],
                "shell_state": shell_state,
            }
            uninstall_state["ok"] = all(
                value for key, value in uninstall_state.items() if key != "shell_state"
            )
    state["uninstall_verification"] = uninstall_state
    if not uninstall_state.get("ok"):
        raise RuntimeError(f"NSIS uninstall left installed state behind: {uninstall_state}")


def evaluate_release(
    installer: Path,
    application: Path,
    package: dict[str, Any],
    signature_loader: Callable[[Path], dict[str, Any]] = _powershell_signature,
    version_loader: Callable[[Path], dict[str, str]] = _powershell_version_info,
    runtime_verifier: Callable[[Path, dict[str, Any]], dict[str, Any]] = verify_electron_runtime_identity,
    extraction_context: Callable[[Path, dict[str, Any]], ContextManager[dict[str, Path]]] = extracted_installer_payload,
    ui_auditor: Callable[[Path, dict[str, Any]], dict[str, Any]] = audit_electron_ui,
    install_context: Callable[[Path, dict[str, Any]], ContextManager[dict[str, Any]]] = installed_nsis_payload,
    source_root: Path = DESKTOP_ROOT,
    package_lock: dict[str, Any] | None = None,
    installer_allowlist_record: tuple[dict[str, Any], str] | None = None,
    installer_receipt_finder: Callable[[str], dict[str, Any]] = _find_committed_allowlist_receipt,
) -> dict[str, Any]:
    policy = package.get("skynetRelease") if isinstance(package.get("skynetRelease"), dict) else {}
    distribution_mode = str(policy.get("distributionMode") or "")
    expected_publisher = str(policy.get("expectedPublisher") or "").strip()
    raw_thumbprints = policy.get("allowedSignerThumbprints")
    allowed_thumbprints = {
        _normalized_thumbprint(value) for value in raw_thumbprints
    } if isinstance(raw_thumbprints, list) else set()
    allowed_thumbprints.discard("")
    policy_errors = _package_contract_errors(package)
    if distribution_mode == "signed" and not expected_publisher:
        policy_errors.append("release_policy_expected_publisher_required")
    if distribution_mode == "signed" and not allowed_thumbprints:
        policy_errors.append("release_policy_signer_thumbprint_required")
    if policy_errors:
        return {
            "schema": "skynet_desktop_release_gate/6",
            "ok": False,
            "distribution_mode": distribution_mode,
            "policy_path": str(POLICY_PATH),
            "policy_errors": policy_errors,
            "artifacts": [],
        }
    version = str(package["version"])
    # One canonical public artifact name, shared with the build stamper and both allowlist
    # schemas. Three independent copies of this string previously drifted apart the moment the
    # naming scheme changed, each failing with a different and misleading error.
    installer_name = _build_stamp.installer_name(version, distribution_mode)
    installer_result = _evaluate_artifact(
        installer, distribution_mode, expected_publisher, allowed_thumbprints, installer_name, signature_loader
    )
    artifacts = [installer_result]
    errors: list[str] = []
    try:
        lock_identity = verify_package_lock_identity(
            package, package_lock if package_lock is not None else load_release_package_lock()
        )
    except Exception as exc:
        lock_identity = {"ok": False, "errors": [f"package_lock_load_failed:{type(exc).__name__}:{exc}"]}
    if not lock_identity.get("ok"):
        errors.append("package_lock_identity_failed")
    try:
        lock_bytes = verify_package_lock_bytes()
    except Exception as exc:
        lock_bytes = {"ok": False, "errors": [f"package_lock_bytes_failed:{type(exc).__name__}:{exc}"]}
    if not lock_bytes.get("ok"):
        errors.append("package_lock_whole_file_not_pinned")
    try:
        allowlist, allowlist_sha256 = (
            installer_allowlist_record
            if installer_allowlist_record is not None
            else load_installer_allowlist()
        )
        wrapper_approval = verify_installer_allowlist(
            installer,
            package,
            allowlist,
            allowlist_sha256,
            receipt_finder=installer_receipt_finder,
            # The SAME tree the asar is verified against. Recomputing the approved source
            # digest from a different root would approve one payload while shipping another.
            source_root=source_root,
        )
    except Exception as exc:
        wrapper_approval = {
            "ok": False,
            "errors": [f"installer_allowlist_load_failed:{type(exc).__name__}:{exc}"],
        }
    if not wrapper_approval.get("ok"):
        errors.append("installer_wrapper_not_dual_approved")
    payload: dict[str, Any] = {}
    identity: dict[str, Any] = {}
    ui_audit: dict[str, Any] = {}
    install_audit: dict[str, Any] = {}
    try:
        with extraction_context(installer, policy) as extracted:
            embedded_result = _evaluate_artifact(
                extracted["application"],
                distribution_mode,
                expected_publisher,
                allowed_thumbprints,
                APPLICATION_NAME,
                signature_loader,
            )
            embedded_result["role"] = "installer_embedded_application"
            artifacts.append(embedded_result)
            loose_asar = application.parent / "resources" / "app.asar"
            payload = {
                "loose_application_sha256": _sha256(application) if application.is_file() else None,
                "embedded_application_sha256": embedded_result.get("sha256"),
                "loose_app_asar_sha256": _sha256(loose_asar) if loose_asar.is_file() else None,
                "embedded_app_asar_sha256": _sha256(extracted["app_asar"]),
            }
            if payload["loose_application_sha256"] != payload["embedded_application_sha256"]:
                errors.append("installer_application_hash_mismatch")
            if payload["loose_app_asar_sha256"] != payload["embedded_app_asar_sha256"]:
                errors.append("installer_app_asar_hash_mismatch")
            identity = {
                "pe": verify_pe_identity(application, package, version_loader),
                "electron_runtime": runtime_verifier(application, policy),
                "asar": verify_asar_identity(loose_asar, package, source_root),
                "extracted_tree": verify_complete_payload_tree(application.parent, extracted["application"].parent),
            }
            if not all(row.get("ok") for row in identity.values()):
                errors.append("electron_identity_verification_failed")
    except Exception as exc:
        errors.append("installer_payload_verification_failed")
        payload = {"detail": str(exc)[:1000]}
    if distribution_mode == "signed" and len(artifacts) == 2 and all(row.get("ok") for row in artifacts):
        thumbprints = {
            _normalized_thumbprint(row.get("signature", {}).get("signer_thumbprint"))
            for row in artifacts
        }
        if "" in thumbprints or len(thumbprints) != 1:
            errors.append("artifact_signer_mismatch")
    # The empirical install -> launch -> uninstall audit is the STRONGEST evidence this gate can
    # produce, so a PAPERWORK failure must not suppress it. Live 2026-08-07: the 0.1.1 allowlist
    # re-bind was unapproved, so `errors` was non-empty and this whole block was skipped -- the
    # installer had never been proven to install, launch or uninstall, and the report showed that
    # silently as `nsis_install_audit: {}`, which reads as "not checked" rather than "not run".
    # CDP advisor (Gemini 3.6 Thinking, 2026-08-07) called the short-circuit "a severe gating
    # logic defect" and prescribed accumulate-all-errors: run the static checks, run the empirical
    # audit REGARDLESS, then fail if any error landed. The one rationale it accepted for skipping
    # is executing an artifact whose integrity is already disproven -- that is EMPIRICAL_AUDIT_BLOCKERS.
    blocking_errors = sorted(set(errors) & EMPIRICAL_AUDIT_BLOCKERS)
    if blocking_errors:
        # Record WHY it did not run. An empty dict cannot be told apart from "ran and found nothing".
        install_audit = {"ok": False, "ran": False, "blocked_by": blocking_errors}
        ui_audit = {"ok": False, "ran": False, "blocked_by": blocking_errors}
    else:
        try:
            with install_context(installer, policy) as installed:
                uninstaller_paths = [
                    path.relative_to(Path(installed["root"])).as_posix()
                    for path in Path(installed["root"]).glob("Uninstall*.exe")
                    if path.is_file()
                ]
                installed_tree = verify_complete_payload_tree(
                    application.parent,
                    Path(installed["root"]),
                    allowed_extra=set(uninstaller_paths),
                )
                ui_audit = ui_auditor(Path(installed["application"]), policy)
                install_audit = {
                    "installer_returncode": installed.get("installer_returncode"),
                    "installed_application_sha256": _sha256(Path(installed["application"])),
                    "loose_application_sha256": _sha256(application),
                    "installed_tree": installed_tree,
                    "install_shell": installed.get("install_shell"),
                }
                if install_audit["installed_application_sha256"] != install_audit["loose_application_sha256"]:
                    errors.append("installed_application_hash_mismatch")
                if not installed_tree.get("ok"):
                    errors.append("installed_payload_tree_mismatch")
                if not ui_audit.get("ok"):
                    errors.append("installed_electron_ui_launch_audit_failed")
            install_audit["uninstaller_returncode"] = installed.get("uninstaller_returncode")
            install_audit["uninstall_verification"] = installed.get("uninstall_verification")
        except Exception as exc:
            ui_audit = {"ok": False, "detail": str(exc)[:1000]}
            errors.append("nsis_install_launch_uninstall_audit_failed")
    return {
        "schema": "skynet_desktop_release_gate/6",
        "ok": len(artifacts) == 2 and all(row.get("ok") for row in artifacts) and not errors,
        "distribution_mode": distribution_mode,
        "policy_path": str(POLICY_PATH),
        "expected_publisher": expected_publisher,
        "allowed_signer_thumbprints": sorted(allowed_thumbprints),
        "artifacts": artifacts,
        "package_lock_identity": lock_identity,
        "package_lock_bytes": lock_bytes,
        "installer_wrapper_approval": wrapper_approval,
        "payload_binding": payload,
        "electron_identity": identity,
        "nsis_install_audit": install_audit,
        "ui_launch_audit": ui_audit,
        "errors": errors,
    }


def main() -> int:
    try:
        package = load_release_package()
        version = str(package.get("version") or "")
        policy = package.get("skynetRelease") if isinstance(package.get("skynetRelease"), dict) else {}
        suffix = "-unsigned" if policy.get("distributionMode") == "unsigned" else ""
        # Resolve the artifact for THIS payload, not merely one matching the version string.
        # dist/ accumulates superseded builds, and the old version-only name resolved to a
        # stale wrapper -- which then failed as hash mismatches against the current tree and
        # read like a corrupt build rather than "you are looking at the wrong file".
        stamp = _build_stamp.compute_stamp(package)
        installer = DESKTOP_ROOT / "dist" / _build_stamp.installer_name(
            version, policy.get("distributionMode"), stamp["buildId"]
        )
        if not installer.is_file():
            # An unstamped build (npm run build:installer:unstamped) still uses the old name.
            legacy = DESKTOP_ROOT / "dist" / f"Skynet Desktop Setup {version}{suffix}.exe"
            if legacy.is_file():
                installer = legacy
        application = DESKTOP_ROOT / "dist" / "win-unpacked" / APPLICATION_NAME
        result = evaluate_release(installer, application, package)
    except Exception as exc:
        result = {
            "schema": "skynet_desktop_release_gate/6",
            "ok": False,
            "policy_path": str(POLICY_PATH),
            "error": "release_gate_failed",
            "detail": str(exc)[:1000],
        }
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--audit-job-wrapper":
        raise SystemExit(_audit_job_wrapper_main(sys.argv[2:]))
    raise SystemExit(main())
