# Security

## The unsigned-binary question, stated plainly

Skynet Desktop releases are **not Authenticode code-signed**. A certificate costs
$200–900/year and this is an independent project. Windows SmartScreen will therefore warn
on first run.

We do not want you to simply click through that warning on trust. The alternative we offer
is verification: every release publishes a SHA-256, and the complete source that produced
the binary is in this repository.

### Verify a download

```powershell
Get-FileHash -Algorithm SHA256 .\Skynet-Desktop-Setup-0.1.1-x64.exe
```

Compare the result with the hash on the
[release page](https://github.com/Zek21/skynet-desktop/releases/latest). If it does not
match **exactly**, do not run the file — and please open an issue.

### Verify the whole chain yourself

```bash
python tools/skynet_desktop_release_gate.py
```

This runs the same fail-closed gate used to produce a release. It proves the `app.asar`
contains exactly the reviewed source by hash, that the installer embeds exactly that
payload, that the Electron runtime matches the pinned upstream build, and that the
installer genuinely installs, launches and uninstalls with zero residue.

Approval binds a **source digest** and a **wrapper-config digest** — about 300 KB of
reviewable text, covering the payload files plus the declarative build config and the NSIS
install script — rather than a 99 MB opaque binary. The point is that a human reviewer can
actually read what they are approving.

## What the app does with your data

- No telemetry, no analytics, no crash reporting to us.
- No backend service of our own.
- It drives AI command-line tools already installed on your machine, under your own
  accounts. Those tools communicate with their respective vendors under their own terms.
- The renderer is context-isolated. Bearer tokens and local sidecar addresses do not cross
  into the renderer process.

## Reporting a vulnerability

Please open a
[security advisory](https://github.com/Zek21/skynet-desktop/security/advisories/new)
rather than a public issue for anything exploitable. For non-sensitive bugs, a normal
issue is perfect.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.
