# Skynet Desktop

**A native Windows desktop app for AI coding agents — one window for Claude, Codex and Gemini, with no terminal and no browser tab.**

[![Download](https://img.shields.io/badge/Download-Windows%20x64-2ea44f?style=for-the-badge)](https://github.com/Zek21/skynet-desktop/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011-0078d6?style=for-the-badge&logo=windows)](https://github.com/Zek21/skynet-desktop/releases/latest)

Skynet Desktop is an Electron application that puts your already-installed AI CLIs behind
one chat window. It finds the `claude`, `codex` and `agy` (Gemini) command-line tools
wherever they actually live on your machine, uses the subscriptions you are already signed
into, and gives them a real desktop UI instead of a terminal prompt.

> **It rides your existing logins.** No API keys to paste, no separate billing. If you can
> run `claude` in a terminal, Skynet Desktop can drive it.

---

## Download

**[⬇ Download Skynet-Desktop-Setup-0.1.1-x64.exe](https://github.com/Zek21/skynet-desktop/releases/latest)** — Windows 10/11, 64-bit, ~95 MB.

Installs per-user (no admin rights required) to
`%LOCALAPPDATA%\Programs\Skynet Desktop`.

### ⚠️ Windows SmartScreen will warn you — here is the honest reason

This release is **not code-signed**. A code-signing certificate costs $200–900/year and
this is an independent project, so Windows shows *"Windows protected your PC"* on first
run. That warning means "we have not seen this publisher before" — not "we detected
malware."

You have two ways to satisfy yourself before running it, and we recommend the second:

1. **Click through:** *More info* → *Run anyway*.
2. **Verify the bytes, then decide.** Every release publishes a SHA-256, and the entire
   source that produced it is in this repository. See [Verifying your download](#verifying-your-download).

If that trade-off is not acceptable to you, that is a completely reasonable position —
build it yourself from source instead. Instructions are below and take about two minutes.

---

## What it does

- **One window, several brains.** Claude, Codex (GPT) and Gemini lanes side by side.
- **Uses the CLIs you already have.** Detects tools installed via npm (including custom
  prefixes), nvm, volta, fnm, pnpm, bun, Scoop, winget, Chocolatey, Homebrew, or a vendor
  installer — not just whatever happens to be on `PATH`.
- **Installs what is missing.** Can fetch a missing CLI from the vendor's own
  hash-verified artifact.
- **Sessions that persist.** Conversations are kept between launches.
- **Frameless native shell.** Real window controls, per-user install, proper Start Menu and
  desktop shortcuts, clean uninstall.
- **Build identity in the titlebar.** Every build shows the content digest that produced it,
  so a bug report always maps back to precise bytes.

## Supporting the project

Skynet Desktop is independent and unfunded. The app shows a sponsorship card **once per
day** — dismissible, never blocking — linking to
[paypal.me/exzilcalanza](https://paypal.me/exzilcalanza).

To be explicit: that is **sponsorship, not equity or investment**. Nothing is gated behind
it and no feature is withheld from people who do not pay.

The QR image in that card is a hash-pinned release payload member and its decoded URL is
asserted by the test suite, so the payment target cannot be changed without failing the
release gate.

## Screenshots

> The titlebar shows the exact build identity — `0.1.1+dirty.<digest>` — so a bug report
> can always be mapped back to the precise bytes that produced it.

---

## Requirements

| | |
|---|---|
| **OS** | Windows 10 or 11, 64-bit |
| **Disk** | ~230 MB installed |
| **Admin rights** | Not required (per-user install) |
| **AI CLIs** | At least one of `claude`, `codex`, or `agy` — the app can install these for you |

---

## Verifying your download

Because the installer is unsigned, verification is done with hashes rather than a
certificate. Compare the SHA-256 of your download against the value published on the
[release page](https://github.com/Zek21/skynet-desktop/releases/latest):

```powershell
Get-FileHash -Algorithm SHA256 .\Skynet-Desktop-Setup-0.1.1-x64.exe
```

**v0.1.1 SHA-256**
```
b1f5c8c30de1706cda56feb93bc6ffceed147cdc0cc895df96f886a7326ef56d
```

Every build also records a machine-readable attestation
(`desktop/release-build-attestation.json`) binding the source content digest to the
installer and `app.asar` hashes it produced.

---

## Build from source

```bash
git clone https://github.com/Zek21/skynet-desktop.git
cd skynet-desktop/desktop
npm ci
npm run build:installer      # -> dist/Skynet-Desktop-Setup-<version>-x64.exe
```

`npm run build:installer` routes through `tools/skynet_desktop_build.py`, which stamps the
build with a content-derived identity before packaging. Requires Python 3.11+ and Node 20+.

---

## How releases are verified

Most projects ask you to trust a signature. This one publishes the checks instead. Every
release runs a fail-closed gate (`tools/skynet_desktop_release_gate.py`) that must prove:

- **Payload identity** — the `app.asar` contains *exactly* the reviewed source files, by
  hash, with no extra or missing members.
- **Wrapper binding** — the installer embeds exactly that `app.asar` and that application
  binary, and its extracted tree matches the built tree file-for-file.
- **Electron identity** — the shipped runtime matches the pinned upstream Electron build.
- **It actually installs** — a real silent install into a scratch directory, verified
  shortcuts and registry entries, a genuine UI launch, then an uninstall that must leave
  *zero* residue. A gate that cannot verify blocks; it never passes by default.

Approval is bound to a **source digest** and a **wrapper-config digest** — roughly 300 KB
of reviewable text — rather than a 99 MB opaque binary, so a human reviewer can actually
read what they are approving.

Run it yourself:

```bash
python tools/skynet_desktop_release_gate.py
```

---

## Uninstalling

Settings → Apps → *Skynet Desktop* → Uninstall, or run
`Uninstall Skynet Desktop.exe` from the install folder. The uninstaller is verified in CI
to remove the install root, both shortcuts, the registry entry and the Start Menu catalog
entry.

---

## FAQ

**Is this affiliated with Anthropic, OpenAI or Google?**
No. It is an independent client that drives their official command-line tools.

**Does it send my code anywhere?**
The app talks to the CLIs installed on your machine; those tools talk to their own vendors
under your own account. Skynet Desktop adds no telemetry and no backend of its own.

**Why is it 95 MB?**
It bundles the Electron/Chromium runtime, the same way Slack, Discord, VS Code and
Claude's own desktop app do.

**Why unsigned?**
Cost. See the SmartScreen section above — verify by hash, or build from source.

**macOS / Linux?**
Not yet. The shell is cross-platform Electron; the installer, shell integration and
release gate are Windows-specific today.

---

## Related

- [Skynet AI](https://github.com/Zek21/Skynet-AI) — the research repository behind this app.
- [firefox-cdp](https://github.com/Zek21/firefox-cdp) — drive Firefox over WebDriver BiDi with a CDP-style API.

## License

[MIT](LICENSE)
