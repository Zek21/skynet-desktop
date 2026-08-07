'use strict';

/**
 * Locks the truths that make the desktop app work on a computer that is NOT this one.
 *
 * Every test here exists because the naive version of the same code was wrong in a way
 * that only shows up on a machine other than the build host: PATH is not where CLIs
 * live, a 0-byte reparse point stats as a file, an npm shim must never be executed as
 * itself, a downloaded archive must not be trusted to stay inside its directory, and an
 * "installed" claim needs bytes that match a published hash.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const provisioning = require('../desktop/lib/cli_provisioning');

/** Build a real .tgz in memory so the extractor is tested against the actual format. */
function makeTarGz(entries) {
  const blocks = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    header.write((entry.mode || 0o644).toString(8).padStart(7, '0') + '\0', 100, 8, 'utf8');
    header.write('0000000\0', 108, 8, 'utf8');
    header.write('0000000\0', 116, 8, 'utf8');
    const body = Buffer.from(entry.body || '', 'utf8');
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8');
    header.write('00000000000\0', 136, 12, 'utf8');
    header.write('        ', 148, 8, 'utf8');            // checksum placeholder
    header.write('0', 156, 1, 'utf8');                    // regular file
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));                        // end of archive
  return zlib.gzipSync(Buffer.concat(blocks));
}

test('a CLI is found outside PATH, which is where a fresh machine actually keeps it', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-discover-'));
  try {
    const home = path.join(temp, 'home');
    const scoop = path.join(home, 'scoop', 'shims');
    fs.mkdirSync(scoop, { recursive: true });
    fs.writeFileSync(path.join(scoop, 'claude.exe'), 'real binary');
    // PATH is EMPTY: this is a GUI process that was launched before the CLI existed.
    const hit = provisioning.discoverCli('claude', {
      fs, platform: 'win32', pathValue: '', env: {}, homedir: home,
    });
    assert.ok(hit, 'a CLI installed by Scoop must not be invisible just because PATH is stale');
    assert.equal(hit.command, path.join(scoop, 'claude.exe'));
    assert.equal(hit.source, 'scoop');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a CLI this app installed outranks anything else with the same name', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-managed-'));
  try {
    const managed = path.join(temp, 'managed');
    const other = path.join(temp, 'other');
    // The managed copy sits where installCli really puts it, not at the root.
    const managedBin = path.join(managed, 'codex', 'vendor', 'x86_64-pc-windows-msvc', 'bin');
    fs.mkdirSync(managedBin, { recursive: true });
    fs.mkdirSync(other, { recursive: true });
    fs.writeFileSync(path.join(managedBin, 'codex.exe'), 'ours');
    fs.writeFileSync(path.join(other, 'codex.exe'), 'theirs');
    const hit = provisioning.discoverCli('codex', {
      // `other` is ON PATH, so this proves precedence and not merely "found something".
      fs, platform: 'win32', arch: 'x64', pathValue: other, env: {}, homedir: temp, managedRoot: managed,
    });
    assert.equal(hit.command, path.join(managedBin, 'codex.exe'));
    assert.equal(hit.source, 'skynet-managed');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a managed install is found at its real nested path, not just at the root', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-nested-'));
  try {
    // installCli unpacks to <root>/<lane>/<memberPath>, and the two vendors nest
    // differently: claude's binary is at the lane root, codex's is under
    // vendor/<triple>/bin. Treating <root> as a flat bin directory found NEITHER, so a
    // lane we installed ourselves lost to whatever copy the system happened to have.
    const managed = path.join(temp, 'clis');
    const codexBin = path.join(managed, 'codex', 'vendor', 'x86_64-pc-windows-msvc', 'bin');
    const claudeDir = path.join(managed, 'claude');
    fs.mkdirSync(codexBin, { recursive: true });
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(path.join(codexBin, 'codex.exe'), 'ours');
    fs.writeFileSync(path.join(claudeDir, 'claude.exe'), 'ours');
    const opts = {
      fs, platform: 'win32', arch: 'x64', pathValue: '', env: {}, homedir: temp, managedRoot: managed,
    };
    const codex = provisioning.discoverCli('codex', opts);
    const claude = provisioning.discoverCli('claude', opts);
    assert.equal(codex.command, path.join(codexBin, 'codex.exe'));
    assert.equal(codex.source, 'skynet-managed');
    assert.equal(claude.command, path.join(claudeDir, 'claude.exe'));
    assert.equal(claude.source, 'skynet-managed');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a zero-byte App Execution Alias is not mistaken for an installed CLI', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-alias-'));
  try {
    // %LOCALAPPDATA%\Microsoft\WindowsApps holds 0-byte reparse points that stat as
    // regular files. Trusting isFile() there "finds" a CLI that only opens the Store.
    const alias = path.join(temp, 'claude.exe');
    fs.writeFileSync(alias, '');
    assert.equal(provisioning.isRunnableFile(fs, alias), false);
    fs.writeFileSync(alias, 'real bytes');
    assert.equal(provisioning.isRunnableFile(fs, alias), true);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a .cmd shim resolves to the real executable and is never itself the command', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-shim-'));
  try {
    const binDir = path.join(temp, 'bin');
    fs.mkdirSync(path.join(binDir, 'node_modules', '.bin'), { recursive: true });
    fs.writeFileSync(path.join(binDir, 'node_modules', '.bin', 'thing.exe'), 'real');
    fs.writeFileSync(
      path.join(binDir, 'thing.cmd'),
      '@ECHO off\r\n"%dp0%\\node_modules\\.bin\\thing.exe" %*\r\n',
    );
    const hit = provisioning.discoverCli('thing', {
      fs, platform: 'win32', pathValue: binDir, env: {}, homedir: temp,
    });
    // Executing thing.cmd would let cmd.exe re-parse the arguments, so a prompt
    // containing & or " could change the command that runs.
    assert.ok(!/\.cmd$/i.test(hit.command), 'the shim itself must never be executed');
    assert.equal(hit.command, path.join(binDir, 'node_modules', '.bin', 'thing.exe'));
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('codex resolves to its vendored native binary when the machine has no Node', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-nonode-'));
  try {
    const binDir = path.join(temp, 'npm');
    const pkg = path.join(binDir, 'node_modules', '@openai', 'codex');
    const vendor = path.join(pkg, 'node_modules', '@openai', 'codex-win32-x64',
      'vendor', 'x86_64-pc-windows-msvc', 'bin');
    fs.mkdirSync(path.join(pkg, 'bin'), { recursive: true });
    fs.mkdirSync(vendor, { recursive: true });
    fs.writeFileSync(path.join(binDir, 'codex.cmd'), 'shim');
    fs.writeFileSync(path.join(pkg, 'bin', 'codex.js'), 'launcher');
    fs.writeFileSync(path.join(vendor, 'codex.exe'), 'native');
    // No node.exe anywhere: the launcher is unusable, but the binary it would have
    // exec'd is right there, and reporting the lane as missing would be false.
    // Every well-known root is redirected INTO the fixture, or the real
    // C:\Program Files\nodejs on the developer's machine silently supplies a node and
    // the test proves nothing about a machine that has none.
    const hit = provisioning.discoverCli('codex', {
      fs,
      platform: 'win32',
      arch: 'x64',
      pathValue: binDir,
      homedir: temp,
      env: {
        APPDATA: path.join(temp, 'empty'),
        LOCALAPPDATA: path.join(temp, 'empty'),
        ProgramFiles: path.join(temp, 'empty'),
        'ProgramFiles(x86)': path.join(temp, 'empty'),
        ProgramData: path.join(temp, 'empty'),
      },
    });
    assert.equal(hit.command, path.join(vendor, 'codex.exe'));
    assert.deepEqual(hit.prefixArgs, []);
    // The launcher sets these before spawning; bypassing it must not change behaviour.
    assert.equal(hit.env.CODEX_MANAGED_BY_NPM, '1');
    assert.equal(hit.env.CODEX_MANAGED_PACKAGE_ROOT, pkg);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('integrity is checked against the published hash, and a single flipped byte fails', () => {
  const bytes = Buffer.from('the exact bytes the registry published');
  const integrity = `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
  assert.equal(provisioning.integrityMatches(bytes, integrity), true);
  assert.equal(provisioning.integrityMatches(Buffer.concat([bytes, Buffer.from('!')]), integrity), false);
  assert.equal(provisioning.integrityMatches(bytes, 'sha512-notevenclose'), false);
  assert.equal(provisioning.integrityMatches(bytes, ''), false);
  // An unknown algorithm must fail closed rather than be treated as "no check needed".
  assert.equal(provisioning.integrityMatches(bytes, 'md5-whatever'), false);
});

test('an archive member that escapes the install directory is refused, not skipped', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-slip-'));
  try {
    const dest = path.join(temp, 'dest');
    fs.mkdirSync(dest, { recursive: true });
    const evil = zlib.gunzipSync(makeTarGz([
      { name: 'package/../../escaped.txt', body: 'pwned' },
    ]));
    assert.throws(
      () => provisioning.extractMembers(evil, dest, { fs }),
      /escapes the install directory/,
    );
    assert.equal(fs.existsSync(path.join(temp, 'escaped.txt')), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('extraction strips the package/ prefix and keeps the executable bit', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-extract-'));
  try {
    const dest = path.join(temp, 'dest');
    const tar = zlib.gunzipSync(makeTarGz([
      { name: 'package/claude.exe', body: 'binary', mode: 0o755 },
      { name: 'package/README.md', body: 'docs', mode: 0o644 },
    ]));
    const written = provisioning.extractMembers(tar, dest, { fs });
    assert.deepEqual(written.sort(), ['README.md', 'claude.exe']);
    assert.equal(fs.readFileSync(path.join(dest, 'claude.exe'), 'utf8'), 'binary');
    if (process.platform !== 'win32') {
      // A downloaded `claude` that is not +x is an install that produced an unusable lane.
      assert.ok(fs.statSync(path.join(dest, 'claude.exe')).mode & 0o111);
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('only the wanted member is unpacked, so a 400 MB archive costs one file', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-subset-'));
  try {
    const dest = path.join(temp, 'dest');
    const tar = zlib.gunzipSync(makeTarGz([
      { name: 'package/vendor/x86_64-pc-windows-msvc/bin/codex.exe', body: 'wanted' },
      { name: 'package/vendor/x86_64-pc-windows-msvc/codex-path/rg.exe', body: 'unwanted' },
    ]));
    const written = provisioning.extractMembers(tar, dest, {
      fs, members: ['vendor/x86_64-pc-windows-msvc/bin/codex.exe'],
    });
    assert.deepEqual(written, ['vendor/x86_64-pc-windows-msvc/bin/codex.exe']);
    assert.equal(fs.existsSync(path.join(dest, 'vendor', 'x86_64-pc-windows-msvc', 'codex-path', 'rg.exe')), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a recorded install is discarded once its executable is gone', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-registry-'));
  try {
    const registryPath = path.join(temp, 'cli_registry.json');
    const exe = path.join(temp, 'codex.exe');
    fs.writeFileSync(exe, 'binary');
    provisioning.recordInstall(fs, registryPath, {
      lane: 'codex', command: exe, prefixArgs: [], source: 'skynet-managed',
      package: '@openai/codex', version: '1.2.3-win32-x64', integrity: 'sha512-x', installedAt: 'now',
    });
    assert.equal(provisioning.recordedCommand(fs, registryPath, 'codex').command, exe);
    fs.rmSync(exe);
    // A remembered path is advisory. Trusting it after the file is gone would report a
    // lane as installed and then fail at spawn time with a confusing error.
    assert.equal(provisioning.recordedCommand(fs, registryPath, 'codex'), null);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('the gemini lane refuses to invent a download it cannot verify', async () => {
  const artifact = await provisioning.resolveArtifact('gemini', { platform: 'win32', arch: 'x64' });
  assert.equal(artifact.ok, false);
  assert.equal(artifact.manual, true);
  assert.match(artifact.url, /^https:\/\//);
  assert.match(artifact.reason, /Antigravity/);
});

test('every lane declares a plan, and only a verifiable one claims it can install', () => {
  for (const id of ['codex', 'claude', 'gemini']) {
    const plan = provisioning.PROVISION_PLANS[id];
    assert.ok(plan, `${id} must declare a provisioning plan`);
    assert.match(plan.manual, /^https:\/\//, `${id} must point at a real vendor page`);
    if (plan.manualOnly) assert.ok(plan.manualReason, `${id} must say WHY it cannot self-install`);
  }
});

test('a non-https download is refused before a single byte is read', async () => {
  await assert.rejects(
    () => provisioning.httpsGet('http://registry.example.test/pkg.tgz', {}),
    /non-https/,
  );
});

test('candidate roots cover the package managers a fresh machine may use', () => {
  const roots = provisioning.candidateBinDirs({
    platform: 'win32', env: {}, homedir: 'C:\\Users\\someone', fs,
  }).map((entry) => entry.source);
  for (const manager of ['npm-global', 'volta', 'pnpm', 'bun', 'scoop', 'winget', 'chocolatey', 'antigravity']) {
    assert.ok(roots.includes(manager), `a machine using ${manager} must not hide its CLIs`);
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-roots-'));
  try {
    // nvm keeps one bin directory PER INSTALLED VERSION, so its entry is a glob. Giving
    // the fixture a real version directory proves the expansion happens rather than
    // just proving a string is present in a list.
    fs.mkdirSync(path.join(temp, '.nvm', 'versions', 'node', 'v22.9.0', 'bin'), { recursive: true });
    const posix = provisioning.candidateBinDirs({
      platform: 'darwin', env: {}, homedir: temp, fs,
    });
    const sources = posix.map((entry) => entry.source);
    for (const manager of ['homebrew', 'nvm', 'volta', 'pnpm', 'asdf', 'mise']) {
      assert.ok(sources.includes(manager), `a machine using ${manager} must not hide its CLIs`);
    }
    assert.ok(
      posix.some((entry) => entry.dir === path.join(temp, '.nvm', 'versions', 'node', 'v22.9.0', 'bin')),
      'the installed node version directory must be expanded, not left as a literal *',
    );
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
