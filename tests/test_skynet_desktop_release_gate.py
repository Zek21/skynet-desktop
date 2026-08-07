from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.skynet_desktop_build_stamp as build_stamp
import tools.skynet_desktop_release_gate as gate
from tools.skynet_desktop_release_gate import CODE_SIGNING_EKU


def _find_repo_root(start: Path) -> Path:
    # Identify the root by the files this suite actually needs -- the Electron entrypoint and
    # the gate under test. It previously keyed off data/skynet_system_registry.json, which is
    # part of the wider private toolchain, so this module raised at IMPORT time in the public
    # skynet-desktop repository where that file legitimately does not exist.
    for candidate in (start, *start.parents):
        if (candidate / "desktop" / "main.js").is_file() and (
            candidate / "tools" / "skynet_desktop_release_gate.py"
        ).is_file():
            return candidate
    raise RuntimeError(f"repository root not found from {start}")


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = _find_repo_root(Path(__file__).resolve())
PUBLISHER = "Example Publisher LLC"
THUMBPRINT = "A" * 40


def signature(**overrides):
    value = {
        "status": "Valid",
        "status_message": "Signature verified.",
        "signature_type": "Authenticode",
        "signer_subject": f"CN={PUBLISHER}",
        "signer_issuer": "CN=Example Public Code Signing CA",
        "signer_thumbprint": THUMBPRINT,
        "signer_not_after": "2027-08-04T00:00:00Z",
        "timestamper_subject": "CN=Example Timestamp Authority",
        "timestamper_thumbprint": "B" * 40,
        "enhanced_key_usage_oids": [CODE_SIGNING_EKU],
    }
    value.update(overrides)
    return value


def unsigned_signature(**overrides):
    value = {
        "status": "NotSigned",
        "status_message": "The file is not digitally signed.",
        "signature_type": "None",
        "signer_subject": "",
        "signer_issuer": "",
        "signer_thumbprint": "",
        "signer_not_after": "",
        "timestamper_subject": "",
        "timestamper_thumbprint": "",
        "enhanced_key_usage_oids": [],
    }
    value.update(overrides)
    return value


def package(**policy_overrides):
    policy = {
        "distributionMode": "unsigned",
        "sevenZipSha256": "C" * 64,
        "electronVersion": "43.2.0",
        "electronBuilderVersion": "26.15.3",
        "electronReferenceExeSha256": "8593db40c0c6e5e3c4b6b0a225b1dc9a549ecdf10f6cf2010cf5b6ce869ce07f",
        "electronReferenceTreeSha256": "9bd20da8b09482a8dbdef46d83ff3d3e480421b8dc1f9c5bd996b08878e41cf5",
        "expectedWindowTitle": "Skynet",
        "requiredUiUrlSuffix": "/renderer/index.html",
        "shortcutName": "Skynet Desktop",
        "appUserModelId": "ai.skynet.desktop",
    }
    policy.update(policy_overrides)
    return {
        "name": "skynet-desktop",
        "productName": "Skynet Desktop",
        "version": "0.1.1",
        "main": "main.js",
        "scripts": {
            "build:installer": "python ../tools/skynet_desktop_build.py",
            "pack": "npm run build:installer && npm run verify:release",
            "verify:release": "python ../tools/skynet_desktop_release_gate.py",
        },
        "devDependencies": {
            "electron": "^43.2.0",
            "electron-builder": "^26.15.3",
        },
        "skynetRelease": policy,
        "build": {
            "appId": "ai.skynet.desktop",
            "forceCodeSigning": policy["distributionMode"] == "signed",
            "asar": True,
            "files": ["main.js", "preload.js", "lib/**/*", "renderer/**/*", "build/**/*"],
            "extraResources": [],
            "win": {"executableName": "Skynet Desktop", "target": ["nsis"],
                    "signExecutable": policy["distributionMode"] != "unsigned"},
            "nsis": {
                "include": "nsis/installer.nsh",
                "shortcutName": "Skynet Desktop",
                "artifactName": "Skynet-Desktop-Setup-${version}-x64.${ext}",
                "createDesktopShortcut": True,
                "createStartMenuShortcut": True,
                "perMachine": False,
                "oneClick": False,
                "allowToChangeInstallationDirectory": True,
                "runAfterFinish": True,
            },
        },
    }


def package_lock(release_package: dict | None = None):
    release_package = release_package or package()
    return {
        "name": release_package["name"],
        "version": release_package["version"],
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": release_package["name"],
                "version": release_package["version"],
                "devDependencies": dict(release_package["devDependencies"]),
            },
            "node_modules/electron": {
                "version": "43.2.0",
                "resolved": "https://registry.npmjs.org/electron/-/electron-43.2.0.tgz",
                "integrity": "sha512-80zvrgG7ZRXD+tD0IyLvrnN9n+veSxadMRsMaC9wKKP3iUbtC7rGM8+dVuCmOb0Rrwwv8ESW4awnUZh9Hbp1fA==",
            },
            "node_modules/electron-builder": {
                "version": "26.15.3",
                "resolved": "https://registry.npmjs.org/electron-builder/-/electron-builder-26.15.3.tgz",
                "integrity": "sha512-a1KM5heqS3gQCZzizXEI8RjJy3QVogULPdeSknt76uLDpBIW/HDGsMg/XgP0riP6PI9COsRvFITKKGDqA8fJxA==",
            },
        },
    }


def pe_info(**overrides):
    value = {
        "file_description": "Skynet Desktop",
        "product_name": "Skynet Desktop",
        "internal_name": "Skynet Desktop",
        "product_version": "0.1.1.0",
    }
    value.update(overrides)
    return value


def _put_header_member(root: dict, member: str, descriptor: dict) -> None:
    node = root
    parts = member.split("/")
    for part in parts[:-1]:
        node = node.setdefault("files", {}).setdefault(part, {})
    node.setdefault("files", {})[parts[-1]] = descriptor


def write_asar(path: Path, members: dict[str, bytes]) -> None:
    header: dict = {}
    offset = 0
    payload = bytearray()
    for name, content in members.items():
        digest = hashlib.sha256(content).hexdigest()
        _put_header_member(header, name, {
            "size": len(content),
            "offset": str(offset),
            "integrity": {
                "algorithm": "SHA256",
                "hash": digest,
                "blockSize": 4194304,
                "blocks": [digest],
            },
        })
        payload.extend(content)
        offset += len(content)
    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    while len(header_json) % 4:
        header_json += b" "
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        struct.pack("<IIII", 4, len(header_json) + 8, len(header_json) + 4, len(header_json))
        + header_json
        + payload
    )


def source_and_asar(tmp_path: Path, release_package: dict) -> tuple[Path, Path]:
    source = tmp_path / "canonical-source"
    members: dict[str, bytes] = {}
    for index, name in enumerate(gate.SOURCE_MEMBERS):
        content = f"reviewed Electron source {index}: {name}\n".encode()
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        members[name] = content
    members["package.json"] = json.dumps({
        "name": "skynet-desktop",
        "productName": "Skynet Desktop",
        "version": release_package["version"],
        "main": "main.js",
        "private": True,
    }).encode()
    app_asar = tmp_path / "app.asar"
    write_asar(app_asar, members)
    return source, app_asar


def artifacts(tmp_path: Path, release_package: dict):
    installer = tmp_path / build_stamp.installer_name(
        release_package["version"], release_package["skynetRelease"]["distributionMode"]
    )
    loose = tmp_path / "win-unpacked" / "Skynet Desktop.exe"
    loose.parent.mkdir(parents=True)
    installer.write_bytes(b"MZ installer fixture")
    loose.write_bytes(b"MZ Electron application fixture")
    source, loose_asar = source_and_asar(tmp_path, release_package)
    real_asar = loose.parent / "resources" / "app.asar"
    real_asar.parent.mkdir(parents=True)
    real_asar.write_bytes(loose_asar.read_bytes())
    return installer, loose, real_asar, source


def extraction_for(application: Path, app_asar: Path):
    @contextlib.contextmanager
    def extract(_installer: Path, _policy: dict):
        yield {"application": application, "app_asar": app_asar}

    return extract


def install_for(application: Path):
    @contextlib.contextmanager
    def install(_installer: Path, _policy: dict):
        state = {
            "root": application.parent,
            "application": application,
            "installer_returncode": 0,
        }
        yield state
        state["uninstaller_returncode"] = 0

    return install


def evaluate(tmp_path: Path, release_package: dict | None = None, **kwargs):
    release_package = release_package or package()
    installer, loose, loose_asar, source = artifacts(tmp_path, release_package)
    defaults = {
        "signature_loader": lambda _path: unsigned_signature(),
        "version_loader": lambda _path: pe_info(),
        "runtime_verifier": lambda _path, _policy: {"ok": True, "reference": "test-fixture"},
        "extraction_context": extraction_for(loose, loose_asar),
        "ui_auditor": lambda _path, _policy: {"ok": True, "target": {"title": "Skynet"}},
        "install_context": install_for(loose),
        "source_root": source,
        "package_lock": package_lock(release_package),
        "installer_allowlist_record": ({
            "schema": "skynet_desktop_installer_allowlist/1",
            "productName": "Skynet Desktop",
            "version": release_package["version"],
            "distributionMode": release_package["skynetRelease"]["distributionMode"],
            "installerName": installer.name,
            "installerSha256": hashlib.sha256(installer.read_bytes()).hexdigest(),
        }, "D" * 64),
        "installer_receipt_finder": lambda _sha: {
            "order_id": "rule1_test_committed",
            "intent_sha256": "E" * 64,
            "state": "COMMITTED",
        },
    }
    defaults.update(kwargs)
    return gate.evaluate_release(installer, loose, release_package, **defaults)


def test_release_gate_accepts_only_bound_unsigned_electron_payload(tmp_path: Path):
    result = evaluate(tmp_path)
    assert result["ok"] is True, result
    assert result["schema"] == "skynet_desktop_release_gate/6"
    assert result["distribution_mode"] == "unsigned"
    assert all(row["signature"]["status"] == "NotSigned" for row in result["artifacts"])
    assert result["electron_identity"]["asar"]["manifest"]["main"] == "main.js"
    assert set(result["electron_identity"]["asar"]["source_members"]) == set(gate.SOURCE_MEMBERS)
    assert result["payload_binding"]["loose_application_sha256"] == result["payload_binding"]["embedded_application_sha256"]
    assert result["payload_binding"]["loose_app_asar_sha256"] == result["payload_binding"]["embedded_app_asar_sha256"]
    assert result["package_lock_identity"]["ok"] is True
    assert result["installer_wrapper_approval"]["ok"] is True


def test_live_gate_rejects_lock_drift_and_unapproved_wrapper_hash(tmp_path: Path):
    drifted = package_lock()
    drifted["version"] = "9.9.9"
    result = evaluate(tmp_path / "lock-drift", package_lock=drifted)
    assert result["ok"] is False
    assert "package_lock_identity_failed" in result["errors"]

    for package_name in ("node_modules/electron", "node_modules/electron-builder"):
        for field, replacement in (
            ("resolved", "https://registry.npmjs.org/decoy/-/decoy-1.0.0.tgz"),
            ("integrity", "sha512-eA=="),
        ):
            substituted = package_lock()
            substituted["packages"][package_name][field] = replacement
            result = evaluate(
                tmp_path / f"lock-{package_name.rsplit('/', 1)[-1]}-{field}",
                package_lock=substituted,
            )
            assert result["ok"] is False
            assert "package_lock_identity_failed" in result["errors"]

    release_package = package()
    installer, _loose, _asar, _source = artifacts(tmp_path / "wrapper", release_package)
    wrong_approval = ({
        "schema": "skynet_desktop_installer_allowlist/1",
        "productName": "Skynet Desktop",
        "version": release_package["version"],
        "distributionMode": "unsigned",
        "installerName": installer.name,
        "installerSha256": "0" * 64,
    }, "D" * 64)
    result = evaluate(
        tmp_path / "wrapper-evaluation",
        installer_allowlist_record=wrong_approval,
    )
    assert result["ok"] is False
    assert "installer_wrapper_not_dual_approved" in result["errors"]


def test_canonical_policy_path_cannot_be_replaced(tmp_path: Path):
    alternate = tmp_path / "attacker-policy.json"
    alternate.write_text(json.dumps(package()), encoding="utf-8")
    with pytest.raises(RuntimeError, match="canonical desktop/package.json"):
        gate.load_release_package(alternate)
    source = (ROOT / "tools" / "skynet_desktop_release_gate.py").read_text(encoding="utf-8")
    assert "--policy" not in source
    assert "--installer" not in source
    assert "--application" not in source


def test_unsigned_release_rejects_signed_or_catalog_artifacts(tmp_path: Path):
    result = evaluate(
        tmp_path,
        signature_loader=lambda _path: signature(),
    )
    assert result["ok"] is False
    for artifact in result["artifacts"]:
        assert "unsigned_release_must_be_authenticode_not_signed" in artifact["errors"]
        assert "unsigned_release_contains_unexpected_signing_identity" in artifact["errors"]

    result = evaluate(
        tmp_path / "catalog",
        signature_loader=lambda _path: unsigned_signature(signature_type="Catalog"),
    )
    assert result["ok"] is False
    assert all("unsigned_release_signature_type_not_none" in row["errors"] for row in result["artifacts"])

    result = evaluate(
        tmp_path / "empty-type",
        signature_loader=lambda _path: unsigned_signature(signature_type=""),
    )
    assert result["ok"] is False
    assert all("unsigned_release_signature_type_not_none" in row["errors"] for row in result["artifacts"])

    result = evaluate(
        tmp_path / "issuer-only",
        signature_loader=lambda _path: unsigned_signature(signer_issuer="unexpected CA"),
    )
    assert result["ok"] is False
    assert all("unsigned_release_contains_unexpected_signing_identity" in row["errors"] for row in result["artifacts"])


def test_signed_mode_still_rejects_wrong_self_signed_or_mismatched_signer(tmp_path: Path):
    signed = package(
        distributionMode="signed",
        expectedPublisher=PUBLISHER,
        allowedSignerThumbprints=[THUMBPRINT, "D" * 40],
    )
    installer, loose, loose_asar, source = artifacts(tmp_path / "mismatch", signed)
    result = gate.evaluate_release(
        installer,
        loose,
        signed,
        signature_loader=lambda path: signature(signer_thumbprint=THUMBPRINT if path == installer else "D" * 40),
        version_loader=lambda _path: pe_info(),
        extraction_context=extraction_for(loose, loose_asar),
        ui_auditor=lambda _path, _policy: {"ok": True},
        source_root=source,
    )
    assert "artifact_signer_mismatch" in result["errors"]


def test_release_gate_rejects_payload_or_reviewed_source_mismatch(tmp_path: Path):
    release_package = package()
    installer, loose, loose_asar, source = artifacts(tmp_path, release_package)
    embedded = tmp_path / "embedded" / "Skynet Desktop.exe"
    embedded_asar = embedded.parent / "app.asar"
    embedded.parent.mkdir()
    embedded.write_bytes(b"different signed application")
    embedded_asar.write_bytes(b"different asar")
    result = gate.evaluate_release(
        installer,
        loose,
        release_package,
        signature_loader=lambda _path: signature(),
        version_loader=lambda _path: pe_info(),
        extraction_context=extraction_for(embedded, embedded_asar),
        ui_auditor=lambda _path, _policy: {"ok": True},
        source_root=source,
    )
    assert "installer_application_hash_mismatch" in result["errors"]
    assert "installer_app_asar_hash_mismatch" in result["errors"]

    source.joinpath("renderer/app.js").write_text("mutated after packaging", encoding="utf-8")
    result = evaluate(tmp_path / "source-drift", source_root=source)
    assert result["ok"] is False
    assert "installer_payload_verification_failed" in result["errors"]


def test_release_gate_rejects_fake_asar_or_non_electron_pe(tmp_path: Path):
    fake_asar = tmp_path / "fake.asar"
    fake_asar.write_bytes(b"not an asar")
    with pytest.raises(RuntimeError, match="invalid outer header"):
        gate.verify_asar_identity(fake_asar, package(), tmp_path)
    pe = gate.verify_pe_identity(
        tmp_path / "renamed-cli.exe",
        package(),
        loader=lambda _path: pe_info(product_name="Skynet CLI", internal_name="skynet.exe"),
    )
    assert pe["ok"] is False
    assert "pe_product_name_mismatch" in pe["errors"]


def test_asar_rejects_every_unreviewed_or_unpacked_member(tmp_path: Path):
    release_package = package()
    source, reviewed_asar = source_and_asar(tmp_path, release_package)
    data_members = {
        name: (source / name).read_bytes()
        for name in gate.SOURCE_MEMBERS
    }
    data_members["package.json"] = json.dumps({
        "name": "skynet-desktop",
        "productName": "Skynet Desktop",
        "version": release_package["version"],
        "main": "main.js",
        "private": True,
    }).encode()
    data_members["renderer/surprise.js"] = b"unreviewed"
    extra_asar = tmp_path / "extra.asar"
    write_asar(extra_asar, data_members)
    with pytest.raises(RuntimeError, match="member set differs"):
        gate.verify_asar_identity(extra_asar, release_package, source)

    with pytest.raises(RuntimeError, match="unpacked or linked"):
        gate._asar_file_descriptors({
            "files": {"main.js": {"size": 1, "offset": "0", "unpacked": True}}
        })

    reviewed_asar.write_bytes(reviewed_asar.read_bytes() + b"unreferenced trailing payload")
    with pytest.raises(RuntimeError, match="trailing unreferenced bytes"):
        gate.verify_asar_identity(reviewed_asar, release_package, source)


def test_release_gate_requires_ui_launch_proof(tmp_path: Path):
    result = evaluate(tmp_path, ui_auditor=lambda _path, _policy: {"ok": False, "error": "no page target"})
    assert result["ok"] is False
    assert "installed_electron_ui_launch_audit_failed" in result["errors"]


def test_real_hash_pinned_7zip_lists_and_extracts(tmp_path: Path):
    reviewed_hash = json.loads((ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))["skynetRelease"]["sevenZipSha256"]
    seven_zip = gate._resolve_7zip(reviewed_hash)
    source = tmp_path / "payload"
    source.mkdir()
    (source / "Skynet Desktop.exe").write_bytes(b"real 7zip extractor fixture")
    archive = tmp_path / "fixture.7z"
    completed = subprocess.run(
        [str(seven_zip), "a", str(archive), str(source / "Skynet Desktop.exe")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "Skynet Desktop.exe" in gate._installer_entries(seven_zip, archive)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    gate._extract_installer_members(seven_zip, archive, extracted, ("Skynet Desktop.exe",))
    assert (extracted / "Skynet Desktop.exe").read_bytes() == b"real 7zip extractor fixture"


def test_7zip_warning_or_failure_code_is_never_accepted(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="warning", stderr=""),
    )
    with pytest.raises(RuntimeError, match=r"list failed \(1\)"):
        gate._installer_entries(tmp_path / "7za.exe", tmp_path / "setup.exe")
    with pytest.raises(RuntimeError, match=r"extraction failed \(1\)"):
        gate._extract_installer_members(
            tmp_path / "7za.exe", tmp_path / "setup.exe", tmp_path, ("Skynet Desktop.exe",)
        )


def test_complete_payload_tree_rejects_missing_or_corrupted_runtime_files(tmp_path: Path):
    loose = tmp_path / "loose"
    extracted = tmp_path / "extracted"
    (loose / "resources").mkdir(parents=True)
    (extracted / "resources").mkdir(parents=True)
    (loose / "Skynet Desktop.exe").write_bytes(b"electron executable")
    (loose / "resources/app.asar").write_bytes(b"reviewed app")
    (loose / "chrome_100_percent.pak").write_bytes(b"chromium runtime")
    (extracted / "Skynet Desktop.exe").write_bytes(b"electron executable")
    (extracted / "resources/app.asar").write_bytes(b"corrupted app")
    result = gate.verify_complete_payload_tree(loose, extracted)
    assert result["ok"] is False
    assert result["missing"] == ["chrome_100_percent.pak"]
    assert result["mismatched"] == ["resources/app.asar"]

    (extracted / "surprise.dll").write_bytes(b"not reviewed")
    result = gate.verify_complete_payload_tree(loose, extracted)
    assert result["ok"] is False
    assert result["unexpected_extra"] == ["surprise.dll"]


def test_tree_snapshot_rejects_links_and_junctions(monkeypatch, tmp_path: Path):
    root = tmp_path / "tree"
    linked = root / "linked"
    linked.mkdir(parents=True)
    (linked / "payload.exe").write_bytes(b"payload")
    original = getattr(Path, "is_junction", lambda _self: False)
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda self: self.name == "linked" or original(self),
        raising=False,
    )
    with pytest.raises(RuntimeError, match="link, junction, or reparse point"):
        gate._tree_snapshot(root)


def test_windows_reparse_metadata_is_mandatory_and_general():
    class Entry:
        path = "C:/tree/reparse"

        def __init__(self, metadata):
            self.metadata = metadata

        def stat(self, *, follow_symlinks):
            assert follow_symlinks is False
            return self.metadata

    assert gate._entry_has_windows_reparse_point(
        Entry(SimpleNamespace(st_file_attributes=0x400, st_reparse_tag=0)),
        require_windows_metadata=True,
    ) is True
    assert gate._entry_has_windows_reparse_point(
        Entry(SimpleNamespace(st_file_attributes=0, st_reparse_tag=0xA000001D)),
        require_windows_metadata=True,
    ) is True
    with pytest.raises(RuntimeError, match="reparse metadata is unavailable"):
        gate._entry_has_windows_reparse_point(
            Entry(SimpleNamespace()), require_windows_metadata=True
        )


def test_snapshot_root_and_asar_source_paths_reject_reparse_points(monkeypatch, tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "file.txt").write_text("payload", encoding="utf-8")
    original = gate._metadata_has_windows_reparse_point
    monkeypatch.setattr(
        gate,
        "_metadata_has_windows_reparse_point",
        lambda metadata, path, **kwargs: Path(path) == root or original(metadata, path, **kwargs),
    )
    with pytest.raises(RuntimeError, match="tree root is a link"):
        gate._tree_snapshot(root)

    source_root = tmp_path / "source"
    source = source_root / "renderer" / "app.js"
    source.parent.mkdir(parents=True)
    source.write_text("reviewed", encoding="utf-8")
    monkeypatch.setattr(
        gate,
        "_metadata_has_windows_reparse_point",
        lambda _metadata, path, **_kwargs: Path(path) == source,
    )
    with pytest.raises(RuntimeError, match="source path contains a reparse point"):
        gate._validate_regular_source_path(source, source_root)


def test_windows_shell_install_checks_bind_shortcuts_registry_and_catalog(tmp_path: Path):
    probe_source = Path(gate.__file__).read_text(encoding="utf-8")
    assert "Get-ChildItem -LiteralPath $shortcutRoot -Filter ($name + '.lnk')" in probe_source
    assert "-File -Recurse -Force -ErrorAction SilentlyContinue" in probe_source

    root = tmp_path / "installed"
    application = root / "Skynet Desktop.exe"
    application.parent.mkdir()
    application.write_bytes(b"MZ")
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    uninstaller.write_bytes(b"MZ")
    state = {
        "shortcuts": [
            {"kind": "user_programs", "target": str(application), "path": "start.lnk", "arguments": ""},
            {"kind": "user_desktop", "target": str(application), "path": "desktop.lnk", "arguments": ""},
        ],
        "uninstall_entries": [{
            "install_location": str(root),
            "uninstall_string": f'"{uninstaller}" /currentuser',
            "quiet_uninstall_string": f'"{uninstaller}" /currentuser /S',
        }],
        "start_apps": [{"name": "Skynet Desktop", "app_id": "ai.skynet.desktop"}],
    }
    assert gate._installed_shell_checks(
        state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )["ok"] is True

    decoy_shortcut_state = {
        **state,
        "shortcuts": [
            *state["shortcuts"],
            {"kind": "common_programs", "target": str(root / "decoy.exe"), "path": "decoy-start.lnk", "arguments": "--debugger"},
            {"kind": "common_desktop", "target": str(root / "decoy.exe"), "path": "decoy-desktop.lnk", "arguments": ""},
        ],
    }
    result = gate._installed_shell_checks(
        decoy_shortcut_state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )
    assert result["ok"] is False
    assert "start_menu_shortcut_missing_or_ambiguous" in result["errors"]
    assert "desktop_shortcut_missing_or_ambiguous" in result["errors"]

    decoy_registry_state = {
        **state,
        "uninstall_entries": [
            *state["uninstall_entries"],
            {
                "install_location": str(Path(str(root) + "-evil")),
                "uninstall_string": '"C:\\decoy\\Uninstall Skynet Desktop.exe" /currentuser',
                "quiet_uninstall_string": '"C:\\decoy\\Uninstall Skynet Desktop.exe" /currentuser /S',
            },
        ],
    }
    result = gate._installed_shell_checks(
        decoy_registry_state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )
    assert result["ok"] is False
    assert "uninstall_registry_entry_missing_invalid_or_ambiguous" in result["errors"]

    state["shortcuts"] = state["shortcuts"][:1]
    result = gate._installed_shell_checks(
        state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )
    assert result["ok"] is False
    assert "desktop_shortcut_missing_or_ambiguous" in result["errors"]

    state["shortcuts"] = [
        {"kind": "user_programs", "target": str(application), "path": "start.lnk", "arguments": ""},
        {"kind": "user_desktop", "target": str(application), "path": "desktop.lnk", "arguments": ""},
    ]
    evil = Path(str(root) + "-evil")
    state["uninstall_entries"] = [{
        "install_location": str(evil),
        "uninstall_string": f'"{evil / "Uninstall Skynet Desktop.exe"}" /S',
        "quiet_uninstall_string": "",
    }]
    result = gate._installed_shell_checks(
        state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )
    assert result["ok"] is False
    assert "uninstall_registry_entry_missing_invalid_or_ambiguous" in result["errors"]

    state["uninstall_entries"] = [{
        "install_location": str(root),
        "uninstall_string": "",
        "quiet_uninstall_string": "",
    }]
    result = gate._installed_shell_checks(
        state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )
    assert result["ok"] is False
    assert "uninstall_registry_entry_missing_invalid_or_ambiguous" in result["errors"]

    state["uninstall_entries"] = [{
        "install_location": str(root),
        "uninstall_string": f'"{uninstaller}" /BROKEN',
        "quiet_uninstall_string": f'"{uninstaller}" /S /BROKEN',
    }]
    state["shortcuts"][0]["arguments"] = "--debugger"
    state["start_apps"] = [
        {"name": "Skynet Desktop", "app_id": "wrong.one"},
        {"name": "Skynet Desktop", "app_id": "wrong.two"},
    ]
    result = gate._installed_shell_checks(
        state, application, root, "Skynet Desktop", "ai.skynet.desktop"
    )
    assert result["ok"] is False
    assert "start_menu_shortcut_missing_or_ambiguous" in result["errors"]
    assert "windows_start_app_catalog_missing_unbound_or_ambiguous" in result["errors"]
    assert "uninstall_registry_entry_missing_invalid_or_ambiguous" in result["errors"]


def test_cleanup_enumerates_descendants_even_if_root_has_already_exited(monkeypatch):
    rows = {
        pid: {
            "pid": pid,
            "parent_pid": 0,
            "executable_path": "C:/audit/Skynet Desktop.exe",
            "creation_date": f"created-{pid}",
            "command_line": "",
        }
        for pid in (4242, 4243, 4244)
    }
    calls = {"count": 0}

    def process_rows():
        calls["count"] += 1
        return list(rows.values()) if calls["count"] <= 4 else []

    monkeypatch.setattr(gate, "_windows_process_rows", process_rows)
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    class ExitedRoot:
        pid = 4242
        returncode = 0

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    result = gate._stop_audit_process(ExitedRoot(), dict(rows), {4244})
    assert result["ok"] is True
    assert result["observed_tree_pids"] == [4242, 4243, 4244]
    assert result["remaining_tree_pids"] == []


def test_process_identity_never_falls_back_when_creation_time_is_missing():
    complete = {
        "pid": 9,
        "executable_path": "C:/audit/Skynet Desktop.exe",
        "creation_date": "created-9",
    }
    assert gate._same_process_identity(complete, dict(complete)) is True
    missing = dict(complete, creation_date="")
    assert gate._same_process_identity(missing, dict(missing)) is False


ELECTRON_REFERENCE = REPO_ROOT / "desktop/node_modules/electron/dist/electron.exe"
# These two tests compare against the real pinned Electron binary, which only exists after
# `npm ci`. On a fresh clone that is a missing PREREQUISITE, not a failure -- reporting it as
# a red test tells a newcomer the project is broken when it simply is not installed yet.
requires_electron_reference = pytest.mark.skipif(
    not ELECTRON_REFERENCE.is_file(),
    reason="pinned Electron reference not present -- run `npm ci` in desktop/ first",
)


@requires_electron_reference
def test_official_electron_reference_self_identity_is_portable():
    reference = ELECTRON_REFERENCE
    assert reference.is_file(), "npm ci must install the pinned Electron reference"
    result = gate._electron_pe_identity(reference, reference)
    assert result["ok"] is True, result
    assert result["section_binding_ok"] is True
    assert result["normalized_header_equal"] is True
    assert result["resource_raw_delta"] == 0


@requires_electron_reference
def test_electron_identity_rejects_entrypoint_mutation_and_overlay(tmp_path: Path):
    reference = ELECTRON_REFERENCE
    spoof = tmp_path / "Skynet Desktop.exe"
    shutil.copy2(reference, spoof)
    with spoof.open("r+b") as handle:
        handle.seek(0x3C)
        pe_offset = struct.unpack("<I", handle.read(4))[0]
        entrypoint_offset = pe_offset + 24 + 16
        handle.seek(entrypoint_offset)
        entrypoint = struct.unpack("<I", handle.read(4))[0]
        handle.seek(entrypoint_offset)
        handle.write(struct.pack("<I", entrypoint ^ 0x10))
    result = gate._electron_pe_identity(reference, spoof)
    assert result["ok"] is False
    assert "electron_pe_execution_header_mismatch" in result["errors"]

    with spoof.open("ab") as handle:
        handle.write(b"unreferenced-overlay")
    with pytest.raises(RuntimeError, match="trailing overlay"):
        gate._pe_image_identity(spoof)


def test_candidate_package_explicitly_declares_unsigned_installable_release():
    candidate = json.loads((ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))
    candidate_lock = json.loads((ROOT / "desktop" / "package-lock.json").read_text(encoding="utf-8"))
    assert gate._package_contract_errors(candidate) == []
    assert gate.verify_package_lock_identity(candidate, candidate_lock)["ok"] is True
    assert candidate["scripts"]["dist"] == "electron-builder --win --dir"
    assert candidate["scripts"]["pack"] == "npm run build:installer && npm run verify:release"
    assert candidate["scripts"]["verify:release"] == "python ../tools/skynet_desktop_release_gate.py"
    assert candidate["build"]["forceCodeSigning"] is False
    assert candidate["build"]["asar"] is True
    # The artifact name is the public download name and deliberately carries no signing or
    # build state -- that belongs in the release notes and the published SHA-256, not in a
    # filename end users read.
    assert candidate["build"]["nsis"]["artifactName"] == "Skynet-Desktop-Setup-${version}-x64.${ext}"
    assert candidate["skynetRelease"]["distributionMode"] == "unsigned"


# ---------------------------------------------------------------------------
# Installer-failure cleanup. The previous shape established the uninstall guard
# only AFTER the install, application and shell-integration checks all passed, so
# every failure path left installer-created shortcuts, Start Apps entries and
# uninstall registry keys behind while TemporaryDirectory quietly removed the files.
# ---------------------------------------------------------------------------


def _shell_state(shortcuts=(), uninstall_entries=(), start_apps=()) -> dict:
    return {
        "shortcuts": list(shortcuts),
        "uninstall_entries": list(uninstall_entries),
        "start_apps": list(start_apps),
    }


def _installed_registry_entry(root: Path) -> dict:
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    return {
        "install_location": str(root),
        "uninstall_string": '"' + str(uninstaller) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(uninstaller) + '" /currentuser /S',
    }


def _drive_failed_install(monkeypatch, tmp_path: Path, installer_returncode: int,
                          create_application: bool):
    """Run installed_nsis_payload against a failing install and capture the commands."""
    commands: list[list[str]] = []
    captured_root: dict[str, Path] = {}
    probes = {"n": 0}

    def fake_shell_state(shortcut_name: str) -> dict:
        probes["n"] += 1
        if probes["n"] == 1:
            return _shell_state()          # clean baseline, so the audit may proceed
        entries = [_installed_registry_entry(captured_root["root"])] if captured_root else []
        return _shell_state(
            shortcuts=[{"kind": "user_desktop", "path": "Skynet Desktop.lnk",
                        "target": "x", "arguments": ""}],
            uninstall_entries=entries,
            start_apps=[{"name": "Skynet Desktop", "app_id": "ai.skynet.desktop"}],
        )

    def fake_run(argv, *args, **kwargs):
        parts = [str(part) for part in argv]
        commands.append(parts)
        if parts[0].endswith("installer.exe"):
            root = Path(parts[2].split("=", 1)[1])
            captured_root["root"] = root
            root.mkdir(parents=True, exist_ok=True)
            # A real NSIS run writes its uninstaller before anything else can fail, and
            # the hardened cleanup will only execute a command bound to that exact file.
            (root / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
            if create_application:
                (root / "Skynet Desktop.exe").write_bytes(b"MZ")
            return SimpleNamespace(returncode=installer_returncode, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_powershell_shell_state", fake_shell_state)
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    installer = tmp_path / "installer.exe"
    installer.write_bytes(b"MZ")
    policy = {"shortcutName": "Skynet Desktop", "appUserModelId": "ai.skynet.desktop"}
    return commands, installer, policy


def _uninstall_calls(commands: list[list[str]]) -> list[list[str]]:
    return [c for c in commands if c[0].endswith("Uninstall Skynet Desktop.exe")]


def test_failed_installer_still_uninstalls_and_keeps_the_original_error(monkeypatch, tmp_path):
    commands, installer, policy = _drive_failed_install(
        monkeypatch, tmp_path, installer_returncode=1, create_application=False
    )
    with pytest.raises(RuntimeError, match=r"silent NSIS install failed \(1\)"):
        with gate.installed_nsis_payload(installer, policy):
            raise AssertionError("the audit body must never run for a failed install")
    quiet = _uninstall_calls(commands)
    assert quiet, "installer-created shell state was never cleaned up: " + repr(commands)
    assert quiet[0][1:] == ["/currentuser", "/S"]


def test_missing_application_still_uninstalls_and_keeps_the_original_error(monkeypatch, tmp_path):
    commands, installer, policy = _drive_failed_install(
        monkeypatch, tmp_path, installer_returncode=0, create_application=False
    )
    with pytest.raises(RuntimeError, match="did not produce Skynet Desktop.exe"):
        with gate.installed_nsis_payload(installer, policy):
            raise AssertionError("the audit body must never run without the application")
    assert _uninstall_calls(commands), \
        "a missing application must not leak installer-created shell state"


def test_ambiguous_shell_integration_still_uninstalls(monkeypatch, tmp_path):
    commands, installer, policy = _drive_failed_install(
        monkeypatch, tmp_path, installer_returncode=0, create_application=True
    )
    # The retry loop is bounded by time.monotonic(), not by sleep(), so patching sleep
    # alone leaves it spinning for a real 30 seconds. Advance the clock instead.
    ticks = iter(range(0, 100_000, 15))
    monkeypatch.setattr(gate.time, "monotonic", lambda: float(next(ticks)))
    monkeypatch.setattr(gate.time, "sleep", lambda *_: None)
    with pytest.raises(RuntimeError, match="installed Windows shell integration failed"):
        with gate.installed_nsis_payload(installer, policy):
            raise AssertionError("the audit body must never run on bad shell integration")
    assert _uninstall_calls(commands), \
        "ambiguous shell state must not be left on the machine"


def test_best_effort_uninstall_never_raises_and_reports_residue(monkeypatch, tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    residue = _shell_state(
        shortcuts=[{"kind": "user_desktop", "path": "Skynet Desktop.lnk",
                    "target": "x", "arguments": ""}],
        uninstall_entries=[_installed_registry_entry(root)],
    )
    monkeypatch.setattr(gate, "_powershell_shell_state", lambda name: residue)
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    record = gate._best_effort_uninstall(root, "Skynet Desktop")
    assert record["clean"] is False
    assert record["residue"]["shortcuts"]


def test_best_effort_uninstall_swallows_probe_failure_instead_of_masking_the_real_error(monkeypatch, tmp_path):
    def explode(_name):
        raise RuntimeError("shell probe exploded")

    monkeypatch.setattr(gate, "_powershell_shell_state", explode)
    record = gate._best_effort_uninstall(tmp_path, "Skynet Desktop")
    assert any("shell_state_probe_failed" in error for error in record["errors"])


def test_quiet_uninstall_commands_ignore_entries_from_another_install_root(tmp_path):
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    (theirs / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    state = _shell_state(uninstall_entries=[
        _installed_registry_entry(mine),
        _installed_registry_entry(theirs),
    ])
    commands = gate._audited_quiet_uninstall_commands(state, mine)
    assert len(commands) == 1
    assert str(mine) in commands[0][0]


# ---------------------------------------------------------------------------
# End-to-end shortcut enumeration. Asserting that two command fragments appear in
# the source proves nothing about what PowerShell actually returns, and synthetic
# decoys named "decoy-start.lnk" could never be emitted by a probe that filters for
# exactly "Skynet Desktop.lnk". This runs the real enumeration against a real tree.
# ---------------------------------------------------------------------------


def test_real_powershell_enumeration_finds_nested_and_hidden_same_name_shortcuts(tmp_path):
    source = Path(gate.__file__).read_text(encoding="utf-8")
    assert "Get-ChildItem -LiteralPath $shortcutRoot -Filter ($name + '.lnk')" in source
    assert "-File -Recurse -Force -ErrorAction SilentlyContinue" in source
    for declared_root in ("Desktop", "CommonDesktopDirectory", "Programs", "CommonPrograms"):
        assert "GetFolderPath('" + declared_root + "')" in source

    root = tmp_path / "Programs"
    (root / "Skynet" / "deeper").mkdir(parents=True)
    (root / "Skynet Desktop.lnk").write_bytes(b"L\x00")
    (root / "Skynet" / "deeper" / "Skynet Desktop.lnk").write_bytes(b"L\x00")
    (root / "Skynet" / "Something Else.lnk").write_bytes(b"L\x00")
    hidden = root / "Skynet" / "hidden"
    hidden.mkdir()
    (hidden / "Skynet Desktop.lnk").write_bytes(b"L\x00")
    attrib = subprocess.run(["attrib", "+h", str(hidden)], check=False, capture_output=True,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    # If attrib silently failed the directory stays ordinary, the count is still 3, and
    # the test would pass WITHOUT ever exercising -Force. Prove the attribute stuck.
    assert attrib.returncode == 0, attrib.stderr or attrib.stdout
    FILE_ATTRIBUTE_HIDDEN = 2
    assert os.stat(hidden).st_file_attributes & FILE_ATTRIBUTE_HIDDEN, \
        "the hidden attribute was not applied, so -Force would not be exercised"

    def count(force: bool) -> str:
        script = (
            "$name = 'Skynet Desktop'; $shortcutRoot = $env:SKYNET_TEST_ROOT; "
            "@(Get-ChildItem -LiteralPath $shortcutRoot -Filter ($name + '.lnk') "
            "-File -Recurse " + ("-Force " if force else "") + "-ErrorAction SilentlyContinue).Count"
        )
        env = os.environ.copy()
        env["SKYNET_TEST_ROOT"] = str(root)
        completed = subprocess.run(
            [gate._powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=60, check=False, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert completed.returncode == 0, completed.stderr
        return completed.stdout.strip()

    # Three same-name shortcuts: top level, nested, and nested inside a HIDDEN folder.
    # "Something Else.lnk" must never be counted.
    assert count(force=True) == "3"
    # The control that makes the assertion above meaningful: without -Force the hidden
    # one is invisible. If these two ever agree, -Force has stopped mattering and the
    # production probe's -Force flag is no longer proven by this test.
    assert count(force=False) == "2"


def test_shell_checks_reject_a_second_same_name_shortcut_the_real_probe_would_emit(tmp_path):
    root = tmp_path / "installed"
    application = root / "Skynet Desktop.exe"
    application.parent.mkdir()
    application.write_bytes(b"MZ")
    (root / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    base = {
        "shortcuts": [
            {"kind": "user_programs", "target": str(application),
             "path": str(root / "Skynet Desktop.lnk"), "arguments": ""},
            {"kind": "user_desktop", "target": str(application),
             "path": str(root / "Desktop" / "Skynet Desktop.lnk"), "arguments": ""},
        ],
        "uninstall_entries": [_installed_registry_entry(root)],
        "start_apps": [{"name": "Skynet Desktop", "app_id": "ai.skynet.desktop"}],
    }
    assert gate._installed_shell_checks(
        base, application, root, "Skynet Desktop", "ai.skynet.desktop")["ok"] is True

    # A REAL duplicate: the same filename the probe filters for, nested one level
    # deeper, pointing at the same application. Only the exact-count rule catches it.
    nested = {
        **base,
        "shortcuts": [
            *base["shortcuts"],
            {"kind": "user_programs", "target": str(application),
             "path": str(root / "Skynet" / "Skynet Desktop.lnk"), "arguments": ""},
        ],
    }
    result = gate._installed_shell_checks(
        nested, application, root, "Skynet Desktop", "ai.skynet.desktop")
    assert result["ok"] is False
    assert "start_menu_shortcut_missing_or_ambiguous" in result["errors"]


# ---------------------------------------------------------------------------
# Hardening of the failure-path cleanup itself. A registry row is untrusted input:
# it self-reports install_location, so matching on that alone would let a row name
# the audited root while pointing QuietUninstallString at any executable with any
# arguments, which the gate would then run.
# ---------------------------------------------------------------------------


def _audited_root_with_uninstaller(tmp_path: Path) -> Path:
    root = tmp_path / "installed"
    root.mkdir()
    (root / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    return root


def test_quiet_command_rejects_an_out_of_root_executable_claiming_the_audited_root(tmp_path):
    root = _audited_root_with_uninstaller(tmp_path)
    evil = tmp_path / "evil.exe"
    evil.write_bytes(b"MZ")
    state = _shell_state(uninstall_entries=[{
        "install_location": str(root),
        "uninstall_string": '"' + str(evil) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(evil) + '" /currentuser /S',
    }])
    assert gate._audited_quiet_uninstall_commands(state, root) == []


def test_quiet_command_rejects_arbitrary_arguments(tmp_path):
    root = _audited_root_with_uninstaller(tmp_path)
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    state = _shell_state(uninstall_entries=[{
        "install_location": str(root),
        "uninstall_string": '"' + str(uninstaller) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(uninstaller) + '" /currentuser /S /RunAnything',
    }])
    assert gate._audited_quiet_uninstall_commands(state, root) == []


def test_quiet_command_accepts_only_the_exact_registered_form(tmp_path):
    root = _audited_root_with_uninstaller(tmp_path)
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    state = _shell_state(uninstall_entries=[{
        "install_location": str(root),
        "uninstall_string": '"' + str(uninstaller) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(uninstaller) + '" /currentuser /S',
    }])
    commands = gate._audited_quiet_uninstall_commands(state, root)
    assert len(commands) == 1
    assert [part.casefold() for part in commands[0][1:]] == ["/currentuser", "/s"]


def test_quiet_command_refuses_when_the_root_holds_more_than_one_uninstaller(tmp_path):
    root = _audited_root_with_uninstaller(tmp_path)
    (root / "Uninstall Extra.exe").write_bytes(b"MZ")
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    state = _shell_state(uninstall_entries=[{
        "install_location": str(root),
        "uninstall_string": '"' + str(uninstaller) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(uninstaller) + '" /currentuser /S',
    }])
    assert gate._audited_quiet_uninstall_commands(state, root) == []


def test_best_effort_uninstall_survives_command_derivation_raising(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "_powershell_shell_state", lambda name: _shell_state())

    def explode(*_args, **_kwargs):
        raise RuntimeError("derivation exploded")

    monkeypatch.setattr(gate, "_audited_quiet_uninstall_commands", explode)
    record = gate._best_effort_uninstall(tmp_path, "Skynet Desktop")
    assert record["clean"] is False
    assert any("command_derivation_failed" in error for error in record["errors"])


def test_a_timed_out_installer_still_triggers_cleanup(monkeypatch, tmp_path):
    """subprocess.run raising is the case the earlier fix still leaked."""
    captured: dict[str, object] = {}
    probes = {"n": 0}

    def fake_shell_state(_name):
        probes["n"] += 1
        return _shell_state()

    def fake_run(argv, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=[str(part) for part in argv], timeout=240)

    def fake_cleanup(install_root, shortcut_name):
        captured["called"] = True
        return {"reason": "test"}

    monkeypatch.setattr(gate, "_powershell_shell_state", fake_shell_state)
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    monkeypatch.setattr(gate, "_best_effort_uninstall", fake_cleanup)
    installer = tmp_path / "installer.exe"
    installer.write_bytes(b"MZ")
    policy = {"shortcutName": "Skynet Desktop", "appUserModelId": "ai.skynet.desktop"}
    with pytest.raises(subprocess.TimeoutExpired):
        with gate.installed_nsis_payload(installer, policy):
            raise AssertionError("the audit body must never run after an installer timeout")
    assert captured.get("called") is True, \
        "an installer that times out may already have written shell state"


# ---------------------------------------------------------------------------
# Whole-file lockfile pin. Pinning only the two direct dependency entries leaves
# ~283 other package entries and every dependency edge unconstrained, so a
# regenerated or edited tree could pass every other check while differing
# arbitrarily. One digest closes that, and a 64-character constant is reviewable
# through a channel that cannot render the 127 KB file itself.
# ---------------------------------------------------------------------------


def test_pinned_lock_digest_is_a_real_sha256_constant():
    assert re.fullmatch(r"[0-9a-f]{64}", gate.PINNED_PACKAGE_LOCK_SHA256)


def test_lock_bytes_verifier_accepts_only_the_pinned_digest(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    lock.write_bytes(b'{"name":"skynet-desktop"}')
    monkeypatch.setattr(gate, "PACKAGE_LOCK_PATH", lock)
    monkeypatch.setattr(gate, "PINNED_PACKAGE_LOCK_SHA256",
                        hashlib.sha256(lock.read_bytes()).hexdigest())
    result = gate.verify_package_lock_bytes(lock)
    assert result["ok"] is True
    assert result["actual"] == result["expected"]


def test_lock_bytes_verifier_rejects_one_changed_byte(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    lock.write_bytes(b'{"name":"skynet-desktop"}')
    monkeypatch.setattr(gate, "PACKAGE_LOCK_PATH", lock)
    monkeypatch.setattr(gate, "PINNED_PACKAGE_LOCK_SHA256",
                        hashlib.sha256(lock.read_bytes()).hexdigest())
    lock.write_bytes(b'{"name":"skynet-desktop" }')   # one space added
    result = gate.verify_package_lock_bytes(lock)
    assert result["ok"] is False
    assert "package_lock_whole_file_hash_mismatch" in result["errors"]


def test_lock_bytes_verifier_fails_closed_when_the_lock_is_absent(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    monkeypatch.setattr(gate, "PACKAGE_LOCK_PATH", lock)
    result = gate.verify_package_lock_bytes(lock)
    assert result["ok"] is False
    assert "package_lock_missing" in result["errors"]


def test_lock_bytes_verifier_refuses_a_non_canonical_path(tmp_path):
    stray = tmp_path / "elsewhere" / "package-lock.json"
    stray.parent.mkdir()
    stray.write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="canonical"):
        gate.verify_package_lock_bytes(stray)


def test_the_pin_matches_the_lockfile_this_release_actually_ships():
    shipped = ROOT / "desktop" / "package-lock.json"
    assert gate.PINNED_PACKAGE_LOCK_SHA256 == hashlib.sha256(shipped.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Executable containment. resolve() FOLLOWS links, so comparing a registry value
# against the resolved path is identity, not containment: a reparse point named
# Uninstall*.exe inside the audited root resolves to a binary OUTSIDE it and the
# comparison then matches. An advisor reproduced exactly that escape.
# ---------------------------------------------------------------------------


def _registry_row(root: Path, exe: Path) -> dict:
    return {
        "install_location": str(root),
        "uninstall_string": '"' + str(exe) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(exe) + '" /currentuser /S',
    }


def test_uninstaller_that_resolves_out_of_the_root_is_refused(tmp_path, monkeypatch):
    """The exact escape an advisor reproduced: an in-root name resolving outside it.

    Creating a real symlink needs a privilege this account does not hold, so the
    resolution is simulated instead of skipped -- the branch under test is the
    containment check, not the OS's ability to make links.
    """
    root = tmp_path / "installed"
    root.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    planted = root / "Uninstall Skynet Desktop.exe"
    planted.write_bytes(b"MZ")

    real_resolve = Path.resolve

    def escaping_resolve(self, *args, **kwargs):
        if self == planted:
            return real_resolve(outside, *args, **kwargs)
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", escaping_resolve)
    state = _shell_state(uninstall_entries=[_registry_row(root, outside)])
    assert gate._audited_quiet_uninstall_commands(state, root) == [], \
        "an in-root name that resolves outside the audited root must never become a command"


def test_out_of_root_executable_named_directly_is_refused(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    (root / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    state = _shell_state(uninstall_entries=[_registry_row(root, outside)])
    assert gate._audited_quiet_uninstall_commands(state, root) == []


def test_uninstaller_must_be_a_regular_file(tmp_path):
    root = tmp_path / "installed"
    (root / "Uninstall Skynet Desktop.exe").mkdir(parents=True)
    state = _shell_state(uninstall_entries=[
        _registry_row(root, root / "Uninstall Skynet Desktop.exe")])
    assert gate._audited_quiet_uninstall_commands(state, root) == []


def test_a_plain_in_root_uninstaller_is_still_accepted(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    commands = gate._audited_quiet_uninstall_commands(
        _shell_state(uninstall_entries=[_registry_row(root, exe)]), root)
    assert len(commands) == 1


def test_a_failing_strict_teardown_still_sweeps_and_reraises(monkeypatch, tmp_path):
    """A strict teardown failure leaves shell state behind unless cleanup also runs there."""
    swept: dict[str, object] = {}
    probes = {"n": 0}

    def fake_shell_state(_name):
        probes["n"] += 1
        return _shell_state()

    def fake_run(argv, *args, **kwargs):
        parts = [str(p) for p in argv]
        if parts[0].endswith("installer.exe"):
            target = Path(parts[2].split("=", 1)[1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "Skynet Desktop.exe").write_bytes(b"MZ")
            (target / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def boom(*_args, **_kwargs):
        raise RuntimeError("silent NSIS uninstall failed (1)")

    def sweep(install_root, shortcut_name):
        swept["called"] = True
        return {"reason": "strict teardown failed"}

    monkeypatch.setattr(gate, "_powershell_shell_state", fake_shell_state)
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    monkeypatch.setattr(gate, "_installed_shell_checks",
                        lambda *a, **k: {"ok": True, "bound_uninstall_entries": []})
    monkeypatch.setattr(gate, "_strict_uninstall_verification", boom)
    monkeypatch.setattr(gate, "_best_effort_uninstall", sweep)

    installer = tmp_path / "installer.exe"
    installer.write_bytes(b"MZ")
    policy = {"shortcutName": "Skynet Desktop", "appUserModelId": "ai.skynet.desktop"}
    with pytest.raises(RuntimeError, match="silent NSIS uninstall failed"):
        with gate.installed_nsis_payload(installer, policy):
            pass
    assert swept.get("called") is True, \
        "a failed strict teardown must not leave installer state on the machine"


# ---------------------------------------------------------------------------
# Root containment and single-derivation. Hardening only the failure path left the
# SUCCESS path deriving its command from _installed_shell_checks, which applies no
# containment at all -- so a command the failure path refuses could still be executed
# on the way out. And a linked or junctioned install ROOT re-opens the escape one
# level up, because resolving it succeeds and every descendant check then passes
# relative to wherever the link pointed.
# ---------------------------------------------------------------------------


def test_a_root_that_resolves_elsewhere_is_refused(tmp_path, monkeypatch):
    root = tmp_path / "installed"
    root.mkdir()
    (root / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")

    real_resolve = Path.resolve

    def escaping_resolve(self, *args, **kwargs):
        if self == root:
            return real_resolve(elsewhere, *args, **kwargs)
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", escaping_resolve)
    state = _shell_state(uninstall_entries=[
        _registry_row(root, elsewhere / "Uninstall Skynet Desktop.exe")])
    assert gate._audited_quiet_uninstall_commands(state, root) == [], \
        "an install root that resolves somewhere else must not anchor containment"


def test_a_root_that_is_not_a_directory_is_refused(tmp_path):
    not_a_dir = tmp_path / "installed"
    not_a_dir.write_bytes(b"MZ")
    assert gate._audited_quiet_uninstall_commands(_shell_state(), not_a_dir) == []


def test_strict_teardown_refuses_a_command_the_hardened_derivation_would_not_return(monkeypatch, tmp_path):
    """The success path must not execute what the failure path would refuse."""
    root = tmp_path / "installed"
    root.mkdir()
    (root / "Uninstall Skynet Desktop.exe").write_bytes(b"MZ")
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")

    monkeypatch.setattr(gate, "_powershell_shell_state", lambda name: _shell_state())
    state = {
        "install_shell": {
            "bound_uninstall_entries": [
                {"parsed_quiet_uninstall_command": [str(outside), "/currentuser", "/S"]}
            ]
        }
    }
    with pytest.raises(RuntimeError, match="not contained within the audited install root"):
        gate._strict_uninstall_verification(state, root, "Skynet Desktop")


def test_strict_teardown_accepts_the_contained_command(monkeypatch, tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    uninstaller.write_bytes(b"MZ")

    calls: list[list[str]] = []

    def fake_state(_name):
        return _shell_state(uninstall_entries=[_registry_row(root, uninstaller)])

    def fake_run(argv, *args, **kwargs):
        calls.append([str(p) for p in argv])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_powershell_shell_state", fake_state)
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    # Advance the clock: a constant monotonic makes the bounded retry loop unbounded.
    ticks = iter(range(0, 100_000, 15))
    monkeypatch.setattr(gate.time, "monotonic", lambda: float(next(ticks)))
    monkeypatch.setattr(gate.time, "sleep", lambda *_: None)
    state = {
        "install_shell": {
            "bound_uninstall_entries": [
                {"parsed_quiet_uninstall_command": [str(uninstaller), "/currentuser", "/S"]}
            ]
        }
    }
    # The uninstall itself runs; teardown then fails only because the fake shell state
    # still reports the entry, which is the fail-closed behaviour we want to keep.
    with pytest.raises(RuntimeError, match="left installed state behind"):
        gate._strict_uninstall_verification(state, root, "Skynet Desktop")
    assert calls and calls[0][0] == str(uninstaller), "the contained uninstaller must be the one run"


# ---------------------------------------------------------------------------
# Hard-link containment bypass. A hard link carries NO reparse point, lstat calls
# it a regular file, and resolve() returns the in-root path itself, so every
# symlink/junction/reparse/containment check passes while the bytes belong to an
# external file. Only the link count betrays it. Unlike symlinks, creating one
# needs no special privilege, so this test uses a REAL hard link.
# ---------------------------------------------------------------------------


def _make_hard_link(link: Path, target: Path) -> bool:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/H", str(link), str(target)],
        capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.returncode == 0 and link.exists()


def test_a_real_hard_link_to_an_outside_binary_is_refused(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ-external-payload")
    planted = root / "Uninstall Skynet Desktop.exe"
    if not _make_hard_link(planted, outside):
        pytest.skip("this filesystem cannot create hard links")

    # Everything the earlier hardening looks at says this file is fine...
    metadata = os.lstat(planted)
    assert stat.S_ISREG(metadata.st_mode)
    assert not planted.is_symlink()
    assert planted.resolve() == planted.absolute()
    # ...and it is still an external binary, caught only by the link count.
    assert metadata.st_nlink > 1
    state = _shell_state(uninstall_entries=[_registry_row(root, planted)])
    assert gate._audited_quiet_uninstall_commands(state, root) == [], \
        "a hard link to an out-of-root binary must never become an executed command"


def test_a_single_named_uninstaller_is_still_accepted(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    assert os.lstat(exe).st_nlink == 1
    commands = gate._audited_quiet_uninstall_commands(
        _shell_state(uninstall_entries=[_registry_row(root, exe)]), root)
    assert len(commands) == 1


def test_empty_install_location_is_accepted_because_real_nsis_leaves_it_blank(tmp_path):
    """Proven live: the shipped NSIS installer writes InstallLocation as an empty string.

    Requiring it to equal the root rejected the genuine uninstaller, which then starved
    the cleanup sweep and left shortcuts and a registry key that could not remove
    themselves. Containment belongs on the executable, not on an advisory field.
    """
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    row = {
        "install_location": "",
        "uninstall_string": '"' + str(exe) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(exe) + '" /currentuser /S',
    }
    commands = gate._audited_quiet_uninstall_commands(_shell_state(uninstall_entries=[row]), root)
    assert len(commands) == 1


def test_a_non_empty_but_wrong_install_location_is_still_rejected(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    row = {
        "install_location": str(tmp_path / "somewhere-else"),
        "uninstall_string": '"' + str(exe) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(exe) + '" /currentuser /S',
    }
    assert gate._audited_quiet_uninstall_commands(_shell_state(uninstall_entries=[row]), root) == []


def test_shell_checks_bind_an_entry_whose_install_location_is_blank(tmp_path):
    root = tmp_path / "installed"
    application = root / "Skynet Desktop.exe"
    application.parent.mkdir()
    application.write_bytes(b"MZ")
    uninstaller = root / "Uninstall Skynet Desktop.exe"
    uninstaller.write_bytes(b"MZ")
    state = {
        "shortcuts": [
            {"kind": "user_programs", "target": str(application), "path": "s.lnk", "arguments": ""},
            {"kind": "user_desktop", "target": str(application), "path": "d.lnk", "arguments": ""},
        ],
        "uninstall_entries": [{
            "install_location": "",
            "uninstall_string": '"' + str(uninstaller) + '" /currentuser',
            "quiet_uninstall_string": '"' + str(uninstaller) + '" /currentuser /S',
        }],
        "start_apps": [{"name": "Skynet Desktop", "app_id": "ai.skynet.desktop"}],
    }
    result = gate._installed_shell_checks(state, application, root, "Skynet Desktop", "ai.skynet.desktop")
    assert result["ok"] is True, result["errors"]


# ---------------------------------------------------------------------------
# Cleanup must not depend on the strict PASS criteria. This is the architecture
# fix for the leak that actually happened: the real NSIS row leaves
# InstallLocation empty, the strict derivation returned nothing, and the sweep
# removed nothing while the audit had already created shortcuts and a registry
# key whose uninstaller was about to be deleted with the temp directory.
# ---------------------------------------------------------------------------


def test_cleanup_still_finds_a_command_when_the_strict_form_is_rejected(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    # Non-canonical arguments: strict validation refuses this, cleanup must not.
    row = {
        "install_location": "",
        "uninstall_string": '"' + str(exe) + '" /currentuser /SomethingElse',
        "quiet_uninstall_string": '"' + str(exe) + '" /currentuser /SomethingElse',
    }
    state = _shell_state(uninstall_entries=[row])
    assert gate._audited_quiet_uninstall_commands(state, root) == [], "strict must refuse"
    fallback = gate._containment_only_uninstall_commands(state, root)
    assert len(fallback) == 1, "cleanup must still be able to remove this install"
    assert fallback[0][0] == str(exe)


def test_cleanup_fallback_still_refuses_an_out_of_root_executable(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    row = {
        "install_location": str(root),
        "uninstall_string": '"' + str(outside) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(outside) + '" /currentuser /S',
    }
    assert gate._containment_only_uninstall_commands(
        _shell_state(uninstall_entries=[row]), root) == [], \
        "relaxing the FORM must never relax CONTAINMENT"


def test_cleanup_fallback_refuses_a_hard_linked_executable(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    planted = root / "Uninstall Skynet Desktop.exe"
    if not _make_hard_link(planted, outside):
        pytest.skip("this filesystem cannot create hard links")
    row = {
        "install_location": "",
        "uninstall_string": '"' + str(planted) + '" /currentuser',
        "quiet_uninstall_string": '"' + str(planted) + '" /currentuser /S',
    }
    assert gate._containment_only_uninstall_commands(
        _shell_state(uninstall_entries=[row]), root) == []


def test_cleanup_fallback_forces_a_silent_switch(tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    row = {
        "install_location": "",
        "uninstall_string": '"' + str(exe) + '"',
        "quiet_uninstall_string": "",
    }
    commands = gate._containment_only_uninstall_commands(_shell_state(uninstall_entries=[row]), root)
    assert len(commands) == 1
    assert "/S" in [part.upper() for part in commands[0][1:]], \
        "cleanup must never open an interactive uninstaller dialog"


def test_best_effort_uninstall_uses_the_fallback_when_strict_yields_nothing(monkeypatch, tmp_path):
    root = tmp_path / "installed"
    root.mkdir()
    exe = root / "Uninstall Skynet Desktop.exe"
    exe.write_bytes(b"MZ")
    row = {
        "install_location": "",
        "uninstall_string": '"' + str(exe) + '" /currentuser /Weird',
        "quiet_uninstall_string": '"' + str(exe) + '" /currentuser /Weird',
    }
    ran: list[list[str]] = []
    monkeypatch.setattr(gate, "_powershell_shell_state",
                        lambda name: _shell_state(uninstall_entries=[row]))

    def fake_run(argv, *a, **k):
        ran.append([str(p) for p in argv])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    record = gate._best_effort_uninstall(root, "Skynet Desktop")
    assert record.get("strict_commands") == 0
    assert record.get("fallback_commands") == 1
    assert ran and ran[0][0] == str(exe), "the contained uninstaller must actually be run"


# ---------------------------------------------------------------------------
# electron-builder's own NSIS helpers are not smuggled files, but the exemption
# must be a NAMED file with KNOWN BYTES, never an open door. This is the same
# "reject the genuine article" failure class as the InstallLocation rule.
# ---------------------------------------------------------------------------


def test_expected_extras_are_pinned_by_hash_not_by_name_alone():
    extras = gate.ELECTRON_BUILDER_EXPECTED_EXTRAS
    assert extras, "there must be an explicit, reviewable list"
    for name, digest in extras.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{name} must be pinned by sha256"
        assert not name.startswith("/") and ".." not in name


def test_the_pinned_elevate_helper_matches_what_electron_builder_actually_ships():
    packaged = REPO_ROOT / "desktop/dist/win-unpacked/resources/elevate.exe"
    if not packaged.is_file():
        pytest.skip("no packaged build present")
    actual = hashlib.sha256(packaged.read_bytes()).hexdigest()
    assert gate.ELECTRON_BUILDER_EXPECTED_EXTRAS["resources/elevate.exe"] == actual


def test_an_extra_file_with_the_wrong_bytes_is_still_rejected():
    extras = gate.ELECTRON_BUILDER_EXPECTED_EXTRAS
    application_files = {"resources/elevate.exe": "0" * 64}
    expected: set[str] = set()
    extra = sorted(
        name for name in set(application_files) - expected
        if application_files.get(name) != extras.get(name)
    )
    assert extra == ["resources/elevate.exe"], "a same-named file with different bytes must fail"


def test_an_unlisted_extra_file_is_still_rejected():
    extras = gate.ELECTRON_BUILDER_EXPECTED_EXTRAS
    application_files = {"resources/backdoor.exe": "a" * 64}
    extra = sorted(
        name for name in set(application_files)
        if application_files.get(name) != extras.get(name)
    )
    assert extra == ["resources/backdoor.exe"]


# ---------------------------------------------------------------------------
# Electron memory-maps resources/app.asar, and Windows keeps the mapping for a
# moment after the process is signalled. Reading or removing the installed tree
# in that window fails with WinError 32, which sank a live gate run on a race
# rather than on a defect.
# ---------------------------------------------------------------------------


def test_wait_for_released_file_returns_true_for_a_free_file(tmp_path):
    target = tmp_path / "app.asar"
    target.write_bytes(b"payload")
    assert gate._wait_for_released_file(target, timeout_seconds=1.0) is True


def test_wait_for_released_file_returns_true_when_the_path_is_absent(tmp_path):
    assert gate._wait_for_released_file(tmp_path / "missing.asar", timeout_seconds=1.0) is True


def test_wait_for_released_file_times_out_instead_of_raising(tmp_path, monkeypatch):
    target = tmp_path / "app.asar"
    target.write_bytes(b"payload")

    def always_locked(self, *args, **kwargs):
        raise OSError(32, "The process cannot access the file")

    monkeypatch.setattr(Path, "open", always_locked)
    # Must report the lock rather than raise out of a cleanup path.
    assert gate._wait_for_released_file(target, timeout_seconds=0.5) is False


def test_wait_for_released_file_requires_write_access_not_merely_read(tmp_path, monkeypatch):
    target = tmp_path / "app.asar"
    target.write_bytes(b"payload")
    modes: list[str] = []
    real_open = Path.open

    def record(self, mode="r", *args, **kwargs):
        modes.append(mode)
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", record)
    gate._wait_for_released_file(target, timeout_seconds=1.0)
    assert modes and all("+" in mode or "w" in mode for mode in modes), \
        "a readable-but-mapped image must not be treated as released"


# ---------------------------------------------------------------------------
# The audit wrapper handshake is proven by a launch NONCE, not by a pid.
# sys.executable can be a venv launcher shim that re-execs the real interpreter
# as a child, so os.getpid() inside the wrapper legitimately differs from the pid
# the caller holds -- observed live as 4740 vs 3692, which made a correct launch
# fail as "handshake identity mismatch".
# ---------------------------------------------------------------------------


def test_wrapper_requires_the_nonce_argument():
    with pytest.raises(RuntimeError, match="nonce"):
        gate._audit_job_wrapper_main(["app.exe", "9222", "profile", "handshake.json"])


def test_handshake_identity_is_not_decided_by_pid():
    source = Path(gate.__file__).read_text(encoding="utf-8")
    launch = source[source.index("def _launch_audit_application"):]
    launch = launch[:launch.index("def audit_electron_ui")]
    assert 'payload.get("nonce") != nonce' in launch, "the nonce must be the identity proof"
    assert 'payload.get("wrapper_pid") != wrapper.pid' not in launch, \
        "a venv shim re-execs, so the wrapper pid is not the spawned pid"


def test_the_nonce_is_unpredictable_and_passed_to_the_wrapper():
    source = Path(gate.__file__).read_text(encoding="utf-8")
    launch = source[source.index("def _launch_audit_application"):]
    launch = launch[:launch.index("def audit_electron_ui")]
    assert "secrets.token_hex" in launch
    assert '"--audit-job-wrapper"' in launch and "nonce]" in launch


def test_wrapper_writes_the_nonce_it_was_given(tmp_path, monkeypatch):
    handshake = tmp_path / "audit_job_handshake.json"
    monkeypatch.setattr(gate, "_install_windows_kill_on_close_job",
                        lambda: (1, SimpleNamespace(CloseHandle=lambda h: None)))

    class FakeChild:
        pid = 4242

        def wait(self):
            return 0

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *a, **k: FakeChild())
    gate._audit_job_wrapper_main(["app.exe", "9222", str(tmp_path), str(handshake), "deadbeef"])
    payload = json.loads(handshake.read_text(encoding="utf-8"))
    assert payload["nonce"] == "deadbeef"
    assert payload["application_pid"] == 4242
    assert payload["containment"] == "windows_job_object_kill_on_close"


# ---------------------------------------------------------------------------
# Residual shortcut sweep. Observed live: the NSIS uninstaller removed the
# registry entry and the Start Apps entry but left the Desktop .lnk behind,
# still targeting the audit's temp install directory.
# ---------------------------------------------------------------------------


def test_residual_sweep_removes_only_shortcuts_pointing_into_the_audited_root(tmp_path, monkeypatch):
    root = tmp_path / "installed"
    root.mkdir()
    mine = tmp_path / "mine.lnk"
    mine.write_bytes(b"L")
    theirs = tmp_path / "theirs.lnk"
    theirs.write_bytes(b"L")
    state = _shell_state(shortcuts=[
        {"kind": "user_desktop", "path": str(mine), "target": str(root / "Skynet Desktop.exe"), "arguments": ""},
        {"kind": "user_desktop", "path": str(theirs), "target": r"C:\Users\someone\Programs\Skynet Desktop\Skynet Desktop.exe", "arguments": ""},
    ])
    monkeypatch.setattr(gate, "_powershell_shell_state", lambda name: state)
    removed = gate._remove_residual_audit_shortcuts(root, "Skynet Desktop")
    assert removed == [str(mine)]
    assert not mine.exists(), "a shortcut into the audited temp root must be removed"
    assert theirs.exists(), "a real user shortcut must NEVER be touched"


def test_residual_sweep_is_silent_when_the_probe_fails(tmp_path, monkeypatch):
    def explode(_name):
        raise RuntimeError("probe down")

    monkeypatch.setattr(gate, "_powershell_shell_state", explode)
    assert gate._remove_residual_audit_shortcuts(tmp_path, "Skynet Desktop") == []


def test_strict_teardown_still_fails_when_residue_cannot_be_swept(monkeypatch, tmp_path):
    """Sweeping must not turn a genuine failure into a pass."""
    root = tmp_path / "installed"
    root.mkdir()
    stubborn = _shell_state(shortcuts=[
        {"kind": "user_desktop", "path": r"C:\elsewhere\Skynet Desktop.lnk",
         "target": r"C:\elsewhere\Skynet Desktop.exe", "arguments": ""},
    ])
    monkeypatch.setattr(gate, "_powershell_shell_state", lambda name: stubborn)
    monkeypatch.setattr(gate, "_audited_quiet_uninstall_commands",
                        lambda state, r: [[str(root / "Uninstall Skynet Desktop.exe"), "/currentuser", "/S"]])
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    ticks = iter(range(0, 100_000, 15))
    monkeypatch.setattr(gate.time, "monotonic", lambda: float(next(ticks)))
    monkeypatch.setattr(gate.time, "sleep", lambda *_: None)
    state = {"install_shell": {"bound_uninstall_entries": [
        {"parsed_quiet_uninstall_command": [str(root / "Uninstall Skynet Desktop.exe"), "/currentuser", "/S"]}]}}
    with pytest.raises(RuntimeError, match="left installed state behind"):
        gate._strict_uninstall_verification(state, root, "Skynet Desktop")
