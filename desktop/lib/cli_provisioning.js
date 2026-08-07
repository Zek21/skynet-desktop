'use strict';

/**
 * Find — or install — the agent CLIs, on a computer that is not this one.
 *
 * Why this exists (2026-08-06): the app located a lane by walking %PATH% for
 * `<name>.exe|.com|.cmd`. That is true on the machine the app was built on and quietly
 * false almost everywhere else. `npm -g` with a custom prefix, nvm/volta/fnm/pnpm/bun,
 * Scoop, winget, Homebrew and the CLIs' own native installers all put the binary
 * somewhere PATH may not mention — and a GUI process inherits the PATH it was LAUNCHED
 * with, so a CLI installed after the app started is invisible until the app restarts.
 * The lane then told the owner "the codex CLI is not installed on this PC" while the
 * CLI sat installed and signed in. That is a false claim, not a missing feature.
 *
 * So a lane now resolves in three widening steps, and if all three fail the app can
 * INSTALL the CLI instead of handing the job back:
 *
 *   1. PATH                — cheap, and correct on a normal machine.
 *   2. KNOWN ROOTS         — every install location the ecosystem really uses, listed
 *                            as data below, including the managed directory this app
 *                            installs into.
 *   3. PACKAGE-MANAGER ASK — `npm prefix -g` and friends, spawned only when the first
 *                            two miss, because it costs ~300ms per manager.
 *
 * The installer deliberately does NOT shell out to `npm install -g`:
 *
 *   - it would require Node on a machine that may have none (the whole point);
 *   - it mutates PATH, and a PATH change is invisible to this already-running process
 *     AND to every process it spawned, so the app would install a CLI it still could
 *     not see until a restart;
 *   - it resolves "latest" at install time, so two machines get different bytes.
 *
 * Instead it fetches the vendor's own platform tarball from the npm registry, verifies
 * the registry's `dist.integrity` sha512 BEFORE unpacking, unpacks into a directory
 * this app owns, and records the ABSOLUTE path to the executable. Nothing on the
 * machine is mutated outside that directory: no PATH, no registry, no elevation. The
 * lane then invokes the absolute path, which is why it works the instant the install
 * finishes rather than after a reboot.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const crypto = require('crypto');

/** Registry base. Overridable so an enterprise mirror or a test can retarget it. */
const DEFAULT_REGISTRY = 'https://registry.npmjs.org';
/** A vendor CLI binary is hundreds of MB; anything larger is not a CLI we asked for. */
const MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 15 * 60 * 1000;
const METADATA_TIMEOUT_MS = 60 * 1000;

/* ===========================================================================
   WHERE CLIs REALLY LIVE

   Data, not code, for the same reason the lane table is data: the next machine
   that hides a CLI somewhere new must cost one line here, not an investigation.
   `glob: true` means the entry contains exactly one `*` segment to expand — that
   is how nvm's per-version bin directories are covered without walking the disk.
   =========================================================================== */

function windowsRoots(env, home) {
  const appData = env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const localAppData = env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
  const programFiles = env.ProgramFiles || 'C:\\Program Files';
  const programFilesX86 = env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  const programData = env.ProgramData || 'C:\\ProgramData';
  return [
    // npm's default global prefix, and the place `npm -g` puts shims.
    { dir: path.join(appData, 'npm'), source: 'npm-global' },
    { dir: path.join(localAppData, 'npm'), source: 'npm-global' },
    // Node itself — corepack/npm shims live beside node.exe.
    { dir: path.join(programFiles, 'nodejs'), source: 'nodejs' },
    { dir: path.join(programFilesX86, 'nodejs'), source: 'nodejs' },
    // nvm-windows: NVM_SYMLINK is the ACTIVE version, so it is worth more than a glob.
    { dir: env.NVM_SYMLINK || '', source: 'nvm-windows' },
    { dir: env.NVM_HOME ? path.join(env.NVM_HOME, '*') : '', source: 'nvm-windows', glob: true },
    { dir: path.join(appData, 'nvm', '*'), source: 'nvm-windows', glob: true },
    // fnm keeps the live shell's node in a per-shell multishell dir; the aliases dir is
    // the stable one an outside process can actually resolve.
    { dir: env.FNM_DIR ? path.join(env.FNM_DIR, 'aliases', 'default') : '', source: 'fnm' },
    { dir: path.join(localAppData, 'fnm_multishells', '*'), source: 'fnm', glob: true },
    // Volta puts a shim per binary in one flat directory.
    { dir: env.VOLTA_HOME ? path.join(env.VOLTA_HOME, 'bin') : '', source: 'volta' },
    { dir: path.join(localAppData, 'Volta', 'bin'), source: 'volta' },
    // pnpm's global bin is PNPM_HOME itself, not a bin/ under it.
    { dir: env.PNPM_HOME || '', source: 'pnpm' },
    { dir: path.join(localAppData, 'pnpm'), source: 'pnpm' },
    { dir: path.join(localAppData, 'Yarn', 'bin'), source: 'yarn' },
    { dir: env.BUN_INSTALL ? path.join(env.BUN_INSTALL, 'bin') : '', source: 'bun' },
    { dir: path.join(home, '.bun', 'bin'), source: 'bun' },
    { dir: env.SCOOP ? path.join(env.SCOOP, 'shims') : '', source: 'scoop' },
    { dir: path.join(home, 'scoop', 'shims'), source: 'scoop' },
    { dir: env.SCOOP_GLOBAL ? path.join(env.SCOOP_GLOBAL, 'shims') : '', source: 'scoop' },
    { dir: path.join(programData, 'scoop', 'shims'), source: 'scoop' },
    { dir: env.ChocolateyInstall ? path.join(env.ChocolateyInstall, 'bin') : '', source: 'chocolatey' },
    { dir: path.join(programData, 'chocolatey', 'bin'), source: 'chocolatey' },
    { dir: path.join(localAppData, 'Microsoft', 'WinGet', 'Links'), source: 'winget' },
    // The CLIs' own native installers, which do not go through any package manager.
    // These paths are read from the vendors' OWN install scripts (verified live
    // 2026-08-06 against chatgpt.com/codex/install.ps1|.sh and claude.ai/install.ps1|.sh),
    // not inferred: the codex standalone default is Programs\OpenAI\Codex\bin with
    // CODEX_INSTALL_DIR as the override, and claude's is ~/.local/bin.
    { dir: env.CODEX_INSTALL_DIR || '', source: 'vendor-installer' },
    { dir: path.join(localAppData, 'Programs', 'OpenAI', 'Codex', 'bin'), source: 'vendor-installer' },
    { dir: path.join(home, '.local', 'bin'), source: 'vendor-installer' },
    { dir: path.join(home, '.claude', 'local'), source: 'vendor-installer' },
    { dir: path.join(home, '.codex', 'bin'), source: 'vendor-installer' },
    // agy ships as one native exe; both layouts are live on real machines.
    { dir: path.join(localAppData, 'agy', 'bin'), source: 'antigravity' },
    { dir: path.join(localAppData, 'Programs', 'Antigravity', 'bin'), source: 'antigravity' },
    { dir: path.join(programFiles, 'Antigravity', 'bin'), source: 'antigravity' },
  ];
}

function posixRoots(env, home) {
  return [
    { dir: '/usr/local/bin', source: 'system' },
    { dir: '/usr/bin', source: 'system' },
    { dir: '/opt/homebrew/bin', source: 'homebrew' },          // Apple Silicon
    { dir: '/usr/local/opt/bin', source: 'homebrew' },
    { dir: '/home/linuxbrew/.linuxbrew/bin', source: 'homebrew' },
    { dir: '/opt/local/bin', source: 'macports' },
    // Both vendors' posix installers default to ~/.local/bin; CODEX_INSTALL_DIR overrides.
    { dir: env.CODEX_INSTALL_DIR || '', source: 'vendor-installer' },
    { dir: path.join(home, '.local', 'bin'), source: 'vendor-installer' },
    { dir: path.join(home, '.claude', 'local'), source: 'vendor-installer' },
    { dir: path.join(home, '.codex', 'bin'), source: 'vendor-installer' },
    { dir: path.join(home, '.npm-global', 'bin'), source: 'npm-global' },
    { dir: path.join(home, '.npm-packages', 'bin'), source: 'npm-global' },
    { dir: path.join(home, 'node_modules', '.bin'), source: 'npm-global' },
    { dir: env.NVM_BIN || '', source: 'nvm' },
    { dir: path.join(env.NVM_DIR || path.join(home, '.nvm'), 'versions', 'node', '*', 'bin'), source: 'nvm', glob: true },
    { dir: path.join(home, '.volta', 'bin'), source: 'volta' },
    { dir: env.VOLTA_HOME ? path.join(env.VOLTA_HOME, 'bin') : '', source: 'volta' },
    { dir: env.PNPM_HOME || '', source: 'pnpm' },
    { dir: path.join(home, '.local', 'share', 'pnpm'), source: 'pnpm' },
    { dir: path.join(home, 'Library', 'pnpm'), source: 'pnpm' },
    { dir: path.join(home, '.yarn', 'bin'), source: 'yarn' },
    { dir: path.join(home, '.config', 'yarn', 'global', 'node_modules', '.bin'), source: 'yarn' },
    { dir: env.BUN_INSTALL ? path.join(env.BUN_INSTALL, 'bin') : '', source: 'bun' },
    { dir: path.join(home, '.bun', 'bin'), source: 'bun' },
    { dir: path.join(home, '.asdf', 'shims'), source: 'asdf' },
    { dir: path.join(home, '.local', 'share', 'mise', 'shims'), source: 'mise' },
    { dir: path.join(env.FNM_DIR || path.join(home, '.fnm'), 'aliases', 'default', 'bin'), source: 'fnm' },
    { dir: path.join(home, '.antigravity', 'bin'), source: 'antigravity' },
  ];
}

/**
 * Every directory worth looking in, de-duplicated and glob-expanded.
 *
 * `managedRoot` — the directory this app installs into — is FIRST on purpose: a CLI we
 * provisioned ourselves is the one we can vouch for, and putting it first means a
 * half-broken system install cannot shadow it.
 */
function candidateBinDirs(options) {
  const opts = options || {};
  const platform = opts.platform || process.platform;
  const env = opts.env || process.env;
  const fsRef = opts.fs || fs;
  const home = opts.homedir || os.homedir();
  const entries = [];
  if (opts.managedRoot) entries.push(...managedBinDirs(opts.managedRoot, platform, opts.arch || process.arch));
  entries.push(...(platform === 'win32' ? windowsRoots(env, home) : posixRoots(env, home)));

  const out = [];
  const seen = new Set();
  for (const entry of entries) {
    if (!entry.dir) continue;
    for (const dir of entry.glob ? expandOneGlob(fsRef, entry.dir) : [entry.dir]) {
      const key = platform === 'win32' ? dir.toLowerCase() : dir;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ dir, source: entry.source });
    }
  }
  return out;
}

/**
 * The bin directories inside the app's own install root.
 *
 * A managed install is NOT flat: `installCli` unpacks to `<root>/<lane>/<memberPath>`,
 * and the two vendors nest differently — claude's binary sits at the lane root while
 * codex's is buried under `vendor/<rust-triple>/bin`. Treating the root itself as a bin
 * directory therefore found nothing, and a lane we had installed ourselves fell through
 * to whatever unrelated copy the system happened to have. Normally the recorded registry
 * answers first; this keeps discovery correct on its own if that file is ever lost.
 */
function managedBinDirs(managedRoot, platform, arch) {
  const out = [];
  for (const plan of Object.values(PROVISION_PLANS)) {
    const member = plan.memberPath(platform, arch);
    const parts = member ? member.slice(0, -1) : [];
    out.push({ dir: path.join(managedRoot, plan.id, ...parts), source: 'skynet-managed' });
  }
  return out;
}

/** Expand a path containing exactly one `*` segment. Never walks deeper than that. */
function expandOneGlob(fsRef, pattern) {
  const marker = pattern.indexOf('*');
  if (marker === -1) return [pattern];
  const head = pattern.slice(0, marker);
  const tail = pattern.slice(marker + 1).replace(/^[\\/]+/, '');
  const parent = head.replace(/[\\/]+$/, '');
  let names;
  try { names = fsRef.readdirSync(parent); } catch (_) { return []; }
  return names.map((name) => (tail ? path.join(parent, name, tail) : path.join(parent, name)));
}

/* ===========================================================================
   RESOLVING A NAME TO SOMETHING SAFE TO EXECUTE
   =========================================================================== */

/**
 * Is this path a real, executable file?
 *
 * `statSync().isFile()` is not enough on Windows. An App Execution Alias in
 * %LOCALAPPDATA%\Microsoft\WindowsApps is a ZERO-BYTE reparse point that stats as a
 * regular file, so a naive check "finds" a python.exe/node.exe that only exists to
 * open the Store. Requiring a non-empty file rejects those without rejecting anything
 * real — no genuine CLI executable is 0 bytes.
 */
function isRunnableFile(fsRef, candidate) {
  try {
    const stat = fsRef.statSync(candidate);
    return stat.isFile() && stat.size > 0;
  } catch (_) {
    return false;
  }
}

function pathEntries(pathValue) {
  return String(pathValue || '')
    .split(path.delimiter)
    .map((entry) => entry.replace(/^"|"$/g, '').trim())
    .filter(Boolean);
}

/**
 * Turn one directory + one command name into `{command, prefixArgs}`.
 *
 * A `.cmd`/`.ps1` shim is NEVER executed as itself: cmd.exe re-parses its arguments, so
 * a prompt containing `&` or `"` could change the command that runs. The shim is read
 * and followed to the real `.exe`, or to node.exe + the `.js` it launches.
 */
function resolveInDirectory(fsRef, dir, name, platform, nodeDirs, options) {
  if (platform !== 'win32') {
    const candidate = path.join(dir, name);
    return isRunnableFile(fsRef, candidate) ? { command: candidate, prefixArgs: [] } : null;
  }
  for (const extension of ['.exe', '.com']) {
    const candidate = path.join(dir, name + extension);
    if (isRunnableFile(fsRef, candidate)) return { command: candidate, prefixArgs: [] };
  }
  for (const extension of ['.cmd', '.bat', '.ps1']) {
    const shim = path.join(dir, name + extension);
    if (!isRunnableFile(fsRef, shim)) continue;
    // The shim proves this directory is where that command is published from. Its TEXT
    // is only one way to learn the target: a pnpm/bun/corepack-generated shim, or one
    // rewritten by a repair tool, may not carry a readable `%dp0%` line at all. So the
    // package layout is checked first and the text is the general fallback.
    const known = knownPackageBinary(fsRef, dir, name, nodeDirs, options);
    if (known) return known;
    const followed = followShim(fsRef, shim, nodeDirs, options);
    if (followed) return followed;
  }
  return null;
}

/**
 * Where each vendor actually puts its executable inside `node_modules`.
 *
 * Written down rather than derived, because the two differ in a way no convention
 * predicts: Claude's bin IS a native `.exe`, while Codex's is a `.js` launcher whose
 * real binary is vendored under a rust target triple.
 */
const KNOWN_PACKAGE_BINARIES = {
  codex: [['@openai', 'codex', 'bin', 'codex.js']],
  claude: [
    ['@anthropic-ai', 'claude-code', 'bin', 'claude.exe'],
    ['@anthropic-ai', 'claude-code', 'bin', 'claude'],
  ],
};

function knownPackageBinary(fsRef, dir, name, nodeDirs, options) {
  for (const parts of KNOWN_PACKAGE_BINARIES[name] || []) {
    const entry = path.join(dir, 'node_modules', ...parts);
    if (!isRunnableFile(fsRef, entry)) continue;
    if (!/\.[cm]?js$/i.test(entry)) return { command: entry, prefixArgs: [] };
    const node = findNodeExecutable(fsRef, nodeDirs);
    if (node) return { command: node, prefixArgs: [entry] };
    const vendored = vendoredNativeBinary(fsRef, entry, options);
    if (vendored) return vendored;
  }
  return null;
}

/**
 * Resolve what an npm-style shim actually launches.
 *
 * The generated `.cmd`/`.ps1` shims name their target relative to the shim's own
 * directory (`%dp0%\..` on cmd, `$PSScriptRoot/..` on PowerShell). Following the text
 * is what lets a CLI installed by ANY package manager resolve without this module
 * knowing that manager's private layout.
 */
function followShim(fsRef, shimPath, nodeDirs, options) {
  const opts = options || {};
  let script;
  try { script = String(fsRef.readFileSync(shimPath, 'utf8')); } catch (_) { return null; }
  const targets = [];
  const patterns = [/%dp0%\\+([^"\r\n]+)/g, /\$PSScriptRoot[\\/]+([^"'\r\n]+)/g, /\$basedir[\\/]+([^"'\r\n]+)/g];
  for (const pattern of patterns) {
    let match = pattern.exec(script);
    while (match) {
      targets.push(match[1].trim());
      match = pattern.exec(script);
    }
  }
  const base = path.dirname(shimPath);
  // A real executable is preferred over "node.exe plus a script": one less moving part,
  // and it still works when the machine's node has since been uninstalled.
  for (const target of targets) {
    if (!/\.exe$/i.test(target) || /(^|[\\/])node\.exe$/i.test(target)) continue;
    const executable = path.join(base, target);
    if (isRunnableFile(fsRef, executable)) return { command: executable, prefixArgs: [] };
  }
  for (const target of targets) {
    if (!/\.[cm]?js$/i.test(target)) continue;
    const entry = path.join(base, target);
    if (!isRunnableFile(fsRef, entry)) continue;
    const node = findNodeExecutable(fsRef, nodeDirs);
    // The launcher is preferred while a node exists: it sets the CODEX_MANAGED_* env
    // vars the vendor's binary reads, so bypassing it would quietly change how the CLI
    // reports and updates itself.
    if (node) return { command: node, prefixArgs: [entry] };
    const vendored = vendoredNativeBinary(fsRef, entry, opts);
    if (vendored) return vendored;
  }
  return null;
}

/**
 * The native binary an npm launcher would have exec'd, found without node.
 *
 * `@openai/codex`'s bin is a `.js` that locates a vendored `codex.exe` and spawns it. On
 * a machine where the CLI is installed but Node has since been removed — or was never on
 * PATH — following the shim dead-ends at "needs node", and the lane reads as missing
 * while a perfectly good 358 MB binary sits on disk. This finds that binary and
 * reproduces the two environment variables the launcher would have set, so the CLI
 * behaves the same way it does when node starts it.
 */
function vendoredNativeBinary(fsRef, jsEntry, options) {
  const opts = options || {};
  const platform = opts.platform || process.platform;
  const arch = opts.arch || process.arch;
  const triple = CODEX_TARGET_TRIPLE[`${platform}-${arch}`];
  const suffix = NPM_PLATFORM_SUFFIX[`${platform}-${arch}`];
  if (!triple || !suffix || !/codex\.[cm]?js$/i.test(jsEntry)) return null;
  const packageRoot = path.dirname(path.dirname(jsEntry));      // .../@openai/codex
  const binary = platform === 'win32' ? 'codex.exe' : 'codex';
  const candidates = [
    // Nested (npm's real layout for an optional platform dep) and hoisted, plus the
    // vendor directory the launcher falls back to when the platform package is absent.
    path.join(packageRoot, 'node_modules', '@openai', `codex-${suffix}`, 'vendor', triple, 'bin', binary),
    path.join(packageRoot, '..', `codex-${suffix}`, 'vendor', triple, 'bin', binary),
    path.join(packageRoot, 'vendor', triple, 'bin', binary),
  ];
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    if (!isRunnableFile(fsRef, resolved)) continue;
    return {
      command: resolved,
      prefixArgs: [],
      env: { CODEX_MANAGED_PACKAGE_ROOT: packageRoot, CODEX_MANAGED_BY_NPM: '1' },
    };
  }
  return null;
}

function findNodeExecutable(fsRef, nodeDirs) {
  for (const dir of nodeDirs || []) {
    for (const name of ['node.exe', 'node']) {
      const candidate = path.join(dir, name);
      if (isRunnableFile(fsRef, candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Find `name` anywhere this machine might plausibly keep it.
 *
 * Returns `{command, prefixArgs, dir, source}` or null. `source` is kept because the
 * UI has to be able to tell the owner WHERE the lane it is about to run came from —
 * "found on PATH" and "installed by Skynet" are different promises.
 */
function discoverCli(name, options) {
  const opts = options || {};
  const fsRef = opts.fs || fs;
  const platform = opts.platform || process.platform;
  const env = opts.env || process.env;
  const pathDirs = pathEntries(opts.pathValue === undefined ? env.PATH || env.Path : opts.pathValue);
  const rootDirs = candidateBinDirs({ ...opts, fs: fsRef, platform, env });
  // node.exe may live anywhere in either list, so a shim can be followed even when the
  // node that installed it is not the node on PATH.
  const nodeDirs = [...pathDirs, ...rootDirs.map((entry) => entry.dir)];
  const probe = (dir, source) => {
    const hit = resolveInDirectory(fsRef, dir, name, platform, nodeDirs, { platform, arch: opts.arch });
    return hit ? { ...hit, dir, source } : null;
  };

  // ORDER IS THE CONTRACT.
  //   1. What this app installed. Those bytes were hash-verified against the vendor's
  //      published artifact, so they must not be shadowed by a same-named copy of
  //      unknown provenance. The runtime already prefers the recorded managed install;
  //      searching in the same order keeps this function from disagreeing with it.
  //   2. PATH, which is correct and cheap on an ordinary machine.
  //   3. Everywhere else the ecosystem really installs to.
  const managed = rootDirs.filter((entry) => entry.source === 'skynet-managed');
  for (const entry of managed) {
    const hit = probe(entry.dir, entry.source);
    if (hit) return hit;
  }
  for (const dir of pathDirs) {
    const hit = probe(dir, 'PATH');
    if (hit) return hit;
  }
  for (const entry of rootDirs) {
    if (entry.source === 'skynet-managed') continue;
    const hit = probe(entry.dir, entry.source);
    if (hit) return hit;
  }
  return null;
}

/**
 * Last resort: ask the package managers where their global bin is.
 *
 * Spawning costs ~300ms per manager, which is why this is not part of the poll path.
 * It exists because a user CAN set `npm config set prefix` to a directory no list will
 * ever guess, and "I installed it and your app can't see it" has to end somewhere.
 */
function managerBinDirs(spawnSyncRef, options) {
  const opts = options || {};
  const runner = spawnSyncRef;
  const platform = opts.platform || process.platform;
  const probes = [
    { manager: 'npm', command: 'npm', args: ['prefix', '-g'], bin: (out) => (platform === 'win32' ? out : path.join(out, 'bin')) },
    { manager: 'pnpm', command: 'pnpm', args: ['bin', '-g'], bin: (out) => out },
    { manager: 'yarn', command: 'yarn', args: ['global', 'bin'], bin: (out) => out },
    { manager: 'bun', command: 'bun', args: ['pm', 'bin', '-g'], bin: (out) => out },
  ];
  const out = [];
  for (const probe of probes) {
    let result;
    try {
      result = runner(probe.command, probe.args, {
        encoding: 'utf8', windowsHide: true, timeout: 20000, shell: platform === 'win32',
      });
    } catch (_) { continue; }
    if (!result || result.status !== 0 || typeof result.stdout !== 'string') continue;
    const first = result.stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)[0];
    if (!first) continue;
    out.push({ dir: probe.bin(first), source: probe.manager });
  }
  return out;
}

/* ===========================================================================
   INSTALLING A CLI THIS APP CAN VOUCH FOR

   Each lane declares the vendor's own platform artifact. The npm registry is used as a
   CONTENT SERVER, not as a package manager: we read the version metadata, fetch exactly
   that tarball, and verify the sha512 the registry published for it. No install script
   runs, so there is no postinstall to trust.
   =========================================================================== */

const NPM_PLATFORM_SUFFIX = {
  'win32-x64': 'win32-x64',
  'win32-arm64': 'win32-arm64',
  'darwin-x64': 'darwin-x64',
  'darwin-arm64': 'darwin-arm64',
  'linux-x64': 'linux-x64',
  'linux-arm64': 'linux-arm64',
};

/** The rust target triple codex names its vendored binary directory after. */
const CODEX_TARGET_TRIPLE = {
  'win32-x64': 'x86_64-pc-windows-msvc',
  'win32-arm64': 'aarch64-pc-windows-msvc',
  'darwin-x64': 'x86_64-apple-darwin',
  'darwin-arm64': 'aarch64-apple-darwin',
  'linux-x64': 'x86_64-unknown-linux-musl',
  'linux-arm64': 'aarch64-unknown-linux-musl',
};

const PROVISION_PLANS = {
  codex: {
    id: 'codex',
    label: 'Codex',
    binary: (platform) => (platform === 'win32' ? 'codex.exe' : 'codex'),
    // Codex publishes its per-platform build as a VERSION of the same package
    // (`@openai/codex@<ver>-win32-x64`), not as a separate package name. Getting this
    // wrong 404s, which is why it is written down rather than derived by convention.
    spec: (platform, arch, version) => {
      const key = `${platform}-${arch}`;
      const suffix = NPM_PLATFORM_SUFFIX[key];
      if (!suffix) return null;
      return { name: '@openai/codex', version: version ? `${version}-${suffix}` : null, base: '@openai/codex', suffix };
    },
    // Inside the tarball: package/vendor/<triple>/bin/codex.exe
    memberPath: (platform, arch) => {
      const triple = CODEX_TARGET_TRIPLE[`${platform}-${arch}`];
      return triple ? ['vendor', triple, 'bin', platform === 'win32' ? 'codex.exe' : 'codex'] : null;
    },
    manual: 'https://developers.openai.com/codex/cli',
  },
  claude: {
    id: 'claude',
    label: 'Claude',
    binary: (platform) => (platform === 'win32' ? 'claude.exe' : 'claude'),
    // Claude publishes a SEPARATE package per platform, versioned in lockstep with the
    // wrapper. Pinning it to the wrapper's version (rather than taking its own `latest`)
    // closes the window where a release is half-published and the two disagree.
    spec: (platform, arch, version) => {
      const suffix = NPM_PLATFORM_SUFFIX[`${platform}-${arch}`];
      return suffix ? { name: `@anthropic-ai/claude-code-${suffix}`, version: version || null, base: '@anthropic-ai/claude-code', suffix } : null;
    },
    // Inside the tarball the executable sits at the package root.
    memberPath: (platform) => [platform === 'win32' ? 'claude.exe' : 'claude'],
    manual: 'https://docs.claude.com/en/docs/claude-code/setup',
  },
  gemini: {
    id: 'gemini',
    label: 'Gemini',
    binary: (platform) => (platform === 'win32' ? 'agy.exe' : 'agy'),
    // agy is not published to npm in any form we can verify. Claiming an install URL we
    // have not proven would be exactly the fabrication the truth invariant forbids, so
    // this lane reports an honest manual step instead of inventing a download.
    spec: () => null,
    memberPath: () => null,
    manual: 'https://antigravity.google/download',
    manualOnly: true,
    manualReason: 'agy ships with Google Antigravity and has no verified standalone download this app can fetch.',
  },
};

function planFor(id) {
  const plan = PROVISION_PLANS[id];
  if (!plan) throw new Error(`no provisioning plan for lane: ${id}`);
  return plan;
}

/** One HTTPS GET, redirect-following, size-capped, returning a Buffer. */
function httpsGet(url, options) {
  const opts = options || {};
  const timeout = opts.timeout || METADATA_TIMEOUT_MS;
  const maxBytes = opts.maxBytes || MAX_DOWNLOAD_BYTES;
  const request = opts.request || https.get;
  const redirectsLeft = opts.redirectsLeft === undefined ? 5 : opts.redirectsLeft;
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(String(url)); } catch (_) { reject(new Error('invalid download URL')); return; }
    if (parsed.protocol !== 'https:') { reject(new Error('refusing a non-https download')); return; }
    const req = request(parsed, { headers: { accept: '*/*', 'user-agent': 'skynet-desktop-provisioner' } }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) { reject(new Error('too many redirects')); return; }
        resolve(httpsGet(new URL(res.headers.location, parsed).toString(), { ...opts, redirectsLeft: redirectsLeft - 1 }));
        return;
      }
      if (status < 200 || status >= 300) {
        res.resume();
        reject(new Error(`download failed: HTTP ${status}`));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          req.destroy(new Error('download exceeded the size limit'));
          return;
        }
        chunks.push(chunk);
        if (opts.onProgress) opts.onProgress(size, Number(res.headers['content-length']) || 0);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => req.destroy(new Error('download timed out')));
  });
}

/**
 * What the registry says the current artifact is: exact version, tarball URL, and the
 * sha512 we will hold the bytes to.
 */
async function resolveArtifact(id, options) {
  const opts = options || {};
  const platform = opts.platform || process.platform;
  const arch = opts.arch || process.arch;
  const registry = String(opts.registry || DEFAULT_REGISTRY).replace(/\/+$/, '');
  const plan = planFor(id);
  if (plan.manualOnly) {
    return { ok: false, manual: true, reason: plan.manualReason, url: plan.manual, lane: id };
  }
  const spec = plan.spec(platform, arch, null);
  if (!spec) return { ok: false, reason: `no published build for ${platform}-${arch}`, lane: id };

  // Metadata reads must NOT carry the caller's progress callback. httpsGet reports
  // progress as (bytes, total), while an install reports it as a {stage, ...} object, so
  // passing it straight through emitted `stage: undefined` ticks during the two metadata
  // fetches — which a progress UI would render as a garbage stage before the real
  // download even starts. Caught by running a real install rather than a mock.
  const metaOpts = { ...opts, onProgress: null };

  // The wrapper package's `latest` is the source of truth for "which version" — both
  // vendors publish the platform build in lockstep with it, and asking the platform
  // package for its OWN latest can catch a release mid-publish.
  const baseMeta = JSON.parse((await httpsGet(`${registry}/${spec.base}/latest`, metaOpts)).toString('utf8'));
  const version = String(baseMeta.version || '').trim();
  if (!version) throw new Error(`registry did not report a version for ${spec.base}`);

  const resolved = plan.spec(platform, arch, version);
  const meta = JSON.parse((await httpsGet(
    `${registry}/${resolved.name}/${resolved.version || 'latest'}`, metaOpts,
  )).toString('utf8'));

  const dist = meta && meta.dist ? meta.dist : {};
  if (!dist.tarball || !dist.integrity) {
    throw new Error(`registry metadata for ${resolved.name} carries no verifiable tarball`);
  }
  return {
    ok: true,
    lane: id,
    package: String(meta.name || resolved.name),
    version: String(meta.version || version),
    tarball: String(dist.tarball),
    integrity: String(dist.integrity),
    unpackedSize: Number(dist.unpackedSize) || 0,
    memberPath: plan.memberPath(platform, arch),
    binary: plan.binary(platform),
  };
}

/** Does `buffer` match an npm `dist.integrity` string (`sha512-<base64>`)? */
function integrityMatches(buffer, integrity) {
  const text = String(integrity || '');
  const separator = text.indexOf('-');
  if (separator === -1) return false;
  const algorithm = text.slice(0, separator).toLowerCase();
  const expected = text.slice(separator + 1);
  if (!['sha512', 'sha384', 'sha256', 'sha1'].includes(algorithm)) return false;
  const actual = crypto.createHash(algorithm).update(buffer).digest('base64');
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ---------------------------------------------------------------------------
   A tar reader, rather than shelling out to `tar`.

   Windows has had bsdtar since 1803, but "has tar" is one more thing that is true here
   and unverified there — and shelling out would hand a downloaded archive to a program
   whose path we would then also have to resolve. Reading the format is 60 lines and
   removes both problems, including the ability to enforce that nothing unpacks outside
   the destination.
   --------------------------------------------------------------------------- */

function readTarEntries(buffer, onEntry) {
  let offset = 0;
  let longName = '';
  while (offset + 512 <= buffer.length) {
    const header = buffer.slice(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;              // end-of-archive
    const rawName = header.slice(0, 100).toString('utf8').replace(/\0.*$/, '');
    const sizeField = header.slice(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeField, 8) || 0;
    const typeFlag = String.fromCharCode(header[156]);
    const modeField = header.slice(100, 108).toString('utf8').replace(/\0.*$/, '').trim();
    const prefix = header.slice(345, 500).toString('utf8').replace(/\0.*$/, '');
    const body = buffer.slice(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;

    if (typeFlag === 'L') {                                     // GNU long name
      longName = body.toString('utf8').replace(/\0.*$/, '');
      continue;
    }
    if (typeFlag === 'x' || typeFlag === 'X' || typeFlag === 'g') {
      // PAX header: the only field we care about is a long path.
      const record = /(?:^|\n)\d+ path=([^\n]+)/.exec(body.toString('utf8'));
      if (record) longName = record[1];
      continue;
    }
    const name = longName || (prefix ? `${prefix}/${rawName}` : rawName);
    longName = '';
    if (typeFlag === '0' || typeFlag === '\0' || typeFlag === '') {
      onEntry({ name, body, mode: parseInt(modeField, 8) || 0o644 });
    }
  }
}

/**
 * Unpack the members we want, and ONLY into `destination`.
 *
 * Every npm tarball roots its contents at `package/`; that prefix is stripped. Each
 * resolved path is then required to stay inside the destination, which is what stops a
 * crafted archive from writing `../../autorun` (zip-slip). A member that escapes is a
 * hard error, not a skipped file — a tarball trying that is not one to salvage.
 */
function extractMembers(tarBuffer, destination, options) {
  const opts = options || {};
  const fsRef = opts.fs || fs;
  const wanted = opts.members || null;                          // null = everything
  const root = path.resolve(destination);
  const written = [];
  readTarEntries(tarBuffer, (entry) => {
    const relative = entry.name.replace(/^\.?\/*/, '').replace(/^package\/?/, '');
    if (!relative) return;
    if (wanted && !wanted.some((member) => relative === member || relative.startsWith(`${member}/`))) return;
    const target = path.resolve(root, relative);
    if (target !== root && !target.startsWith(root + path.sep)) {
      throw new Error(`archive member escapes the install directory: ${entry.name}`);
    }
    fsRef.mkdirSync(path.dirname(target), { recursive: true });
    // 0o755 for anything the archive marked executable: a downloaded `claude` that is
    // not +x on macOS/Linux is an install that silently produced an unusable lane.
    const mode = entry.mode & 0o111 ? 0o755 : 0o644;
    fsRef.writeFileSync(target, entry.body, { mode });
    written.push(relative);
  });
  return written;
}

/** Remove a directory tree if it exists, tolerating a partially-written one. */
function removeTree(fsRef, target) {
  try { fsRef.rmSync(target, { recursive: true, force: true }); } catch (_) { /* nothing to remove */ }
}

/**
 * Install one lane's CLI into a directory this app owns, and hand back the absolute
 * path to the executable.
 *
 * Fail-CLOSED at every step: metadata without an integrity hash, bytes that do not
 * match it, an archive member that escapes, or a missing executable after unpacking all
 * abort with the real reason. A half-installed lane is removed rather than left to be
 * discovered later as a mystery.
 */
async function installCli(id, options) {
  const opts = options || {};
  const fsRef = opts.fs || fs;
  const platform = opts.platform || process.platform;
  const arch = opts.arch || process.arch;
  const managedRoot = String(opts.managedRoot || '');
  if (!managedRoot) throw new Error('installCli needs a managedRoot to install into');

  const artifact = await resolveArtifact(id, { ...opts, platform, arch });
  if (!artifact.ok) return { ok: false, lane: id, manual: Boolean(artifact.manual), reason: artifact.reason, url: artifact.url };

  const report = (stage, detail) => { if (opts.onProgress) opts.onProgress({ lane: id, stage, ...detail }); };
  report('download', { version: artifact.version, bytes: 0, total: artifact.unpackedSize });

  const tgz = await httpsGet(artifact.tarball, {
    ...opts,
    timeout: DOWNLOAD_TIMEOUT_MS,
    onProgress: (bytes, total) => report('download', { bytes, total }),
  });

  report('verify', { bytes: tgz.length });
  if (!integrityMatches(tgz, artifact.integrity)) {
    return { ok: false, lane: id, reason: 'downloaded bytes do not match the integrity hash the registry published' };
  }

  report('extract', {});
  const tar = zlib.gunzipSync(tgz, { maxOutputLength: MAX_DOWNLOAD_BYTES });
  const laneRoot = path.join(managedRoot, id);
  const staging = `${laneRoot}.incoming`;
  removeTree(fsRef, staging);
  fsRef.mkdirSync(staging, { recursive: true });
  let executable;
  try {
    const memberPath = artifact.memberPath;
    extractMembers(tar, staging, { fs: fsRef, members: memberPath ? [memberPath.join('/')] : null });
    executable = path.join(staging, ...(memberPath || [artifact.binary]));
    if (!isRunnableFile(fsRef, executable)) {
      throw new Error(`the archive did not contain ${memberPath ? memberPath.join('/') : artifact.binary}`);
    }
  } catch (err) {
    removeTree(fsRef, staging);
    return { ok: false, lane: id, reason: String(err && err.message ? err.message : err) };
  }

  // Swap in atomically-ish: the old tree goes first, then the staged one takes its name.
  // A rename cannot merge two trees, so a stale binary can never survive an upgrade.
  removeTree(fsRef, laneRoot);
  fsRef.renameSync(staging, laneRoot);
  const installed = path.join(laneRoot, ...(artifact.memberPath || [artifact.binary]));
  report('done', { path: installed });
  return {
    ok: true,
    lane: id,
    command: installed,
    prefixArgs: [],
    source: 'skynet-managed',
    package: artifact.package,
    version: artifact.version,
    integrity: artifact.integrity,
    installedAt: new Date().toISOString(),
  };
}

/* ===========================================================================
   THE PERSISTED ANSWER

   Discovery is re-run cheaply on every poll, but an INSTALL is expensive and its result
   must survive a restart. This records only what a later run can re-verify: the path,
   and what put it there. It is advisory — a recorded path whose file has since been
   deleted is discarded rather than trusted.
   =========================================================================== */

function readRegistry(fsRef, registryPath) {
  try {
    const parsed = JSON.parse(String(fsRef.readFileSync(registryPath, 'utf8')));
    return parsed && typeof parsed === 'object' && parsed.lanes ? parsed : { lanes: {} };
  } catch (_) {
    return { lanes: {} };
  }
}

function writeRegistry(fsRef, registryPath, value) {
  const temp = `${registryPath}.${process.pid}.tmp`;
  fsRef.mkdirSync(path.dirname(registryPath), { recursive: true });
  fsRef.writeFileSync(temp, JSON.stringify(value, null, 2), 'utf8');
  fsRef.renameSync(temp, registryPath);
}

function recordInstall(fsRef, registryPath, result) {
  const current = readRegistry(fsRef, registryPath);
  current.lanes[result.lane] = {
    command: result.command,
    prefixArgs: result.prefixArgs || [],
    source: result.source,
    package: result.package,
    version: result.version,
    integrity: result.integrity,
    installedAt: result.installedAt,
  };
  writeRegistry(fsRef, registryPath, current);
  return current;
}

/** A previously-installed lane, but only if its executable is still really there. */
function recordedCommand(fsRef, registryPath, id) {
  const entry = readRegistry(fsRef, registryPath).lanes[id];
  if (!entry || !entry.command) return null;
  if (!isRunnableFile(fsRef, entry.command)) return null;
  return { command: entry.command, prefixArgs: entry.prefixArgs || [], source: entry.source || 'skynet-managed' };
}

module.exports = {
  DEFAULT_REGISTRY,
  PROVISION_PLANS,
  candidateBinDirs,
  discoverCli,
  expandOneGlob,
  extractMembers,
  followShim,
  httpsGet,
  installCli,
  integrityMatches,
  isRunnableFile,
  managerBinDirs,
  readTarEntries,
  recordInstall,
  recordedCommand,
  resolveArtifact,
  resolveInDirectory,
  vendoredNativeBinary,
};
