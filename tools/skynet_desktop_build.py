"""Build the Skynet Desktop installer WITH a build identity baked in.

`electron-builder --win` on its own produces an artifact whose only identity is the version
string, which is how two different payloads both came to be called 0.1.1 (app.asar c13382ec vs
6bf1ba06). This driver stamps every build first, so:

  * the packaged app.asar's package.json carries buildId + sourceDigest + sourceCommit,
  * the installer FILENAME carries the build id, so two payloads cannot share a name on disk,
  * an attestation lands next to the artifact recording exactly what was produced.

The attestation is what lets release approval move upstream: it binds reviewable source (a
commit and a content digest) to the mechanically-derived installer hash, instead of asking a
human to eyeball a 99.7MB NSIS wrapper.

Usage (from desktop/, via `npm run build:installer`):
    python ../tools/skynet_desktop_build.py [--dir] [--skip-build]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
DESKTOP_ROOT = ROOT / "desktop"
DIST_ROOT = DESKTOP_ROOT / "dist"

sys.path.insert(0, str(ROOT))

from tools import skynet_desktop_build_stamp as build_stamp  # noqa: E402


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _electron_builder_command() -> list[str]:
    """Prefer the pinned local binary; fall back to npx rather than a global of unknown version.

    The release policy pins electronBuilderVersion, so silently building with whatever
    electron-builder happens to be on PATH would defeat the point of pinning it.
    """
    local = DESKTOP_ROOT / "node_modules" / ".bin"
    for candidate in ("electron-builder.cmd", "electron-builder"):
        binary = local / candidate
        if binary.is_file():
            return [str(binary)]
    npx = shutil.which("npx.cmd") or shutil.which("npx")
    if npx:
        return [npx, "--no-install", "electron-builder"]
    raise RuntimeError("electron-builder is not installed in desktop/node_modules")


def run_build(stamp: dict[str, Any], dir_only: bool = False) -> int:
    command = [
        *_electron_builder_command(),
        "--win",
        *(["--dir"] if dir_only else []),
        *build_stamp.electron_builder_args(stamp),
    ]
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=str(DESKTOP_ROOT), check=False)
    return completed.returncode


def write_attestation(stamp: dict[str, Any]) -> dict[str, Any]:
    """Record what the build ACTUALLY produced, not what it intended to produce.

    Hashes are read back off disk after the build. A missing artifact is recorded as null
    rather than omitted, so a consumer can tell "not built" from "not recorded".
    """
    installer_name = build_stamp.installer_name(
        stamp["version"], stamp.get("distributionMode"), stamp["buildId"]
    )
    installer = DIST_ROOT / installer_name
    unpacked = DIST_ROOT / "win-unpacked"
    attestation = dict(stamp)
    attestation.update({
        "installerName": installer_name,
        "installerSha256": _sha256(installer),
        "installerBytes": installer.stat().st_size if installer.is_file() else None,
        "appAsarSha256": _sha256(unpacked / "resources" / "app.asar"),
        "applicationSha256": _sha256(unpacked / "Skynet Desktop.exe"),
        "packageLockSha256": _sha256(DESKTOP_ROOT / "package-lock.json"),
    })
    build_stamp.ATTESTATION_PATH.write_text(
        json.dumps(attestation, indent=2) + "\n", encoding="utf-8"
    )
    return attestation


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the stamped Skynet Desktop installer")
    parser.add_argument("--dir", action="store_true", help="unpacked build only, no installer")
    parser.add_argument("--skip-build", action="store_true", help="re-stamp and re-attest without rebuilding")
    args = parser.parse_args(list(argv) if argv is not None else None)

    package = json.loads((DESKTOP_ROOT / "package.json").read_text(encoding="utf-8"))
    stamp = build_stamp.compute_stamp(package)
    print(f"build id: {stamp['buildId']}", flush=True)
    if not stamp["sourceMembersClean"]:
        # Not fatal -- local iteration is normal -- but never silent: the commit in this
        # attestation does not vouch for these bytes.
        print(
            "WARNING: reviewed source members are uncommitted; this build is identified by "
            f"content digest only ({', '.join(stamp['dirtyMembers']) or 'unknown members'})",
            file=sys.stderr,
            flush=True,
        )

    if not args.skip_build:
        code = run_build(stamp, dir_only=args.dir)
        if code != 0:
            print(f"electron-builder failed ({code})", file=sys.stderr)
            return code

    attestation = write_attestation(stamp)
    print(json.dumps({
        "buildId": attestation["buildId"],
        "installerName": attestation["installerName"],
        "installerSha256": attestation["installerSha256"],
        "appAsarSha256": attestation["appAsarSha256"],
        "attestation": str(build_stamp.ATTESTATION_PATH),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
