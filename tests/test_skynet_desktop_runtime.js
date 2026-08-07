'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const runtime = require('../desktop/lib/sidecar_runtime');

test('SSE decoder preserves frames across arbitrary chunk boundaries', () => {
  const frames = [];
  const decoder = runtime.createSseDecoder((frame) => frames.push(frame), 1024);
  for (const chunk of ['event: del', 'ta\r\ndata: {"text":"hel', 'lo"}\r\n\r', '\nevent: done\n', 'data: {"ok":true}\n\n']) {
    decoder.push(chunk);
  }
  decoder.end();
  assert.deepEqual(frames, [
    { event: 'delta', data: { text: 'hello' }, raw: '{"text":"hello"}' },
    { event: 'done', data: { ok: true }, raw: '{"ok":true}' },
  ]);
});

test('SSE decoder fails closed at its byte limit', () => {
  const decoder = runtime.createSseDecoder(() => {}, 8);
  assert.throws(() => decoder.push('123456789'), /exceeded limit/);
});

test('renderer trust is identity-bound to the owned webContents', () => {
  const webContents = {};
  const windowRef = { isDestroyed: () => false, webContents };
  assert.equal(runtime.isTrustedRenderer(windowRef, { sender: webContents }), true);
  assert.equal(runtime.isTrustedRenderer(windowRef, { sender: {} }), false);
  assert.equal(runtime.isTrustedRenderer({ isDestroyed: () => true, webContents }, { sender: webContents }), false);
});

test('repository discovery ignores machine-specific packaged resource pointers', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-runtime-'));
  try {
    const repo = path.join(temp, 'repo');
    const resources = path.join(temp, 'installed', 'resources');
    fs.mkdirSync(path.join(repo, 'tools'), { recursive: true });
    fs.mkdirSync(resources, { recursive: true });
    fs.writeFileSync(path.join(repo, 'tools', 'skynet_app_server.py'), '# proof\n');
    fs.writeFileSync(path.join(resources, 'skynet-root.json'), JSON.stringify({ repoRoot: repo }));
    assert.equal(runtime.discoverRepoRoot({
      fs,
      dirname: path.join(temp, 'elsewhere'),
      execPath: path.join(temp, 'installed', 'Skynet.exe'),
      resourcesPath: resources,
      envRoot: '',
    }), null);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('Windows tree termination credits only verified process death', () => {
  let alive = true;
  const child = { pid: 4242, kill: () => { alive = false; } };
  const success = runtime.terminateProcessTree(child, {
    platform: 'win32',
    spawnSync: (command) => {
      if (command === 'tasklist') return { status: 0, stdout: alive ? '"python.exe","4242"' : '' };
      alive = false;
      return { status: 0, stdout: '', stderr: '' };
    },
    killFn: () => { if (!alive) { const error = new Error('gone'); error.code = 'ESRCH'; throw error; } },
  });
  assert.equal(success.ok, true);
  assert.equal(success.command_status, 0);

  const failure = runtime.terminateProcessTree({ pid: 4243, kill: () => {} }, {
    platform: 'win32',
    spawnSync: (command) => command === 'tasklist'
      ? { status: 0, stdout: '"python.exe","4243"' }
      : { status: 1, error: new Error('denied') },
    killFn: () => {},
  });
  assert.equal(failure.ok, false);
  assert.equal(failure.alive_after, true);

  let taskkillCalled = false;
  const unknown = runtime.terminateProcessTree({ pid: 4244, kill: () => {} }, {
    platform: 'win32',
    spawnSync: (command) => {
      if (command === 'tasklist') return { status: 1, stdout: '', error: new Error('tasklist denied') };
      taskkillCalled = true;
      return { status: 0, stdout: '', stderr: '' };
    },
    killFn: () => {},
  });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.method, 'liveness_unknown');
  assert.equal(unknown.probe_state, 'unknown');
  assert.equal(unknown.alive_after, null);
  assert.equal(taskkillCalled, false);
});

/* ===========================================================================
   Models & fleet surface in the PACKAGED runtime.

   The owner's 2026-08-05 screenshot of the shipped app (build
   skynet-desktop-portable-v1) is what proved these belong here and not only in the
   Python sidecar: that build showed two lanes, both reading "subscription default".
   =========================================================================== */

const portable = require('../desktop/lib/portable_runtime');

test('the same lane may fill several role rows, including the orchestrator', () => {
  const ready = new Set(['codex', 'claude']);
  const config = portable.validateOrchestration({
    enabled: true,
    orchestrator: { lane: 'codex', model: 'gpt-5.6-sol' },
    workers: [
      { lane: 'codex', model: 'gpt-5.6-sol' },
      { lane: 'codex', model: 'gpt-5.5' },
      { lane: 'codex', model: 'gpt-5.6-sol' },
    ],
  }, ready);
  assert.equal(config.workers.length, 3);
  assert.deepEqual(config.workers[0], config.workers[2]);
  assert.equal(config.orchestrator.lane, config.workers[0].lane);
});

test('the original string role shape still loads', () => {
  const config = portable.validateOrchestration(
    { enabled: true, orchestrator: 'codex', workers: ['claude'] },
    new Set(['codex', 'claude']),
  );
  assert.deepEqual(config.orchestrator, { lane: 'codex', model: '' });
  assert.deepEqual(config.workers, [{ lane: 'claude', model: '' }]);
});

test('a role row on a lane that is not authenticated is still refused', () => {
  assert.throws(
    () => portable.validateOrchestration(
      { enabled: true, orchestrator: 'codex', workers: ['claude'] },
      new Set(['codex']),
    ),
    /worker is not an authenticated lane: claude/,
  );
});

test('a chosen model reaches the provider command line', () => {
  const spec = portable.providerCommand('codex', {
    workDir: 'C:/work', outputFile: 'C:/tmp/out.txt', model: 'gpt-5.5',
  }, null);
  assert.ok(spec.args.includes('--model'));
  assert.equal(spec.args[spec.args.indexOf('--model') + 1], 'gpt-5.5');
  assert.ok(spec.args.includes('C:/work'), 'the chosen folder must be the codex -C target');
});

test('a user-supplied endpoint is SSRF-checked before a key is sent to it', async () => {
  const resolve = async (host) => {
    if (host === 'evil.example') return [{ address: '169.254.169.254' }];
    if (host === 'inside.example') return [{ address: '10.0.0.5' }];
    return [{ address: '160.79.104.10' }];
  };
  assert.equal((await portable.checkEndpointUrl('http://169.254.169.254', { resolve })).ok, false);
  assert.equal((await portable.checkEndpointUrl('https://evil.example', { resolve })).ok, false);
  const inside = await portable.checkEndpointUrl('https://inside.example', { resolve });
  assert.equal(inside.ok, false);
  assert.match(inside.reason, /private address/);
  // Declared local servers are the ONE way a private address is permitted.
  const declared = await portable.checkEndpointUrl('http://127.0.0.1:11434', { resolve, allowLocal: true });
  assert.equal(declared.ok, true);
  assert.equal((await portable.checkEndpointUrl('https://api.anthropic.com', { resolve })).ok, true);
  // http to a public host would put the key on the wire in clear text.
  assert.equal((await portable.checkEndpointUrl('http://api.anthropic.com', { resolve })).ok, false);
});

test('a stored key is masked and never returned in the public shape', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-keys-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    const entry = app.publicKey({
      id: 'api-abc', provider: 'anthropic', key_hint: 'sk-a…4f2a',
      secret: { scheme: 'os_keystore', value: 'ZW5jcnlwdGVk' },
      models: ['claude-opus-5'], model: 'claude-opus-5', verified: true,
    });
    assert.equal(entry.key_hint, 'sk-a…4f2a');
    assert.equal(entry.protection, 'os_keystore');
    assert.equal(Object.prototype.hasOwnProperty.call(entry, 'secret'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(entry, 'key'), false);
    assert.equal(portable.maskKey('sk-ant-0123456789abcdef'), 'sk-a…cdef');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('the working folder is reported truthfully and a missing one falls back', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-ws-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    fs.mkdirSync(app.workDir, { recursive: true });
    const chosen = path.join(temp, 'project');
    fs.mkdirSync(chosen);
    const info = app.setWorkspace(chosen);
    assert.equal(info.path, path.resolve(chosen));
    assert.equal(info.source, 'user');
    assert.equal(info.exists, true);
    assert.equal(app.effectiveWorkspace(), path.resolve(chosen));

    fs.rmSync(chosen, { recursive: true, force: true });
    const gone = app.workspaceInfo();
    assert.equal(gone.exists, false);
    assert.match(gone.reason, /no longer exists/);
    assert.equal(app.effectiveWorkspace(), app.workDir, 'a vanished folder must not be used as cwd');

    assert.throws(() => app.setWorkspace(path.join(temp, 'never-created')), /does not exist/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('lane rows carry the models, kind and reason the panel needs', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-lanes-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    app.subscriptions = {
      codex: { installed: false, authenticated: false, runtime_status: 'unavailable', detail: 'command unavailable' },
      claude: { installed: true, authenticated: true, runtime_status: 'ready', detail: 'ready' },
    };
    const rows = app.laneRows();
    const claude = rows.find((row) => row.id === 'claude');
    const codex = rows.find((row) => row.id === 'codex');
    assert.equal(claude.kind, 'cli');
    assert.ok(claude.models.includes('claude-opus-5'), 'a ready lane must offer real model ids');
    assert.equal(claude.reason, '', 'a ready lane has nothing to explain');
    // A missing CLI must say why AND offer the way out. The old text ("not installed on
    // this PC. Sign in to it") told the owner to do something impossible for a binary
    // that is not there, which is the dead end this lane row exists to end.
    assert.match(codex.reason, /not on this PC/, 'an unusable lane must say why in words');
    assert.match(codex.reason, /install it for you/, 'a missing CLI must offer the install');
    assert.equal(codex.can_install, true, 'a fetchable CLI is installable from the app');
    assert.equal(codex.can_orchestrate, false);
    // An INSTALLED lane must offer neither install route — a "Get it" button beside a
    // working lane is the app failing to know its own state.
    assert.equal(claude.can_install, false, 'an installed lane must not offer an install');
    assert.equal(claude.manual_install_url, '', 'an installed lane must not offer a download page');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a failed turn still leaves a session on disk, and a missing session recovers', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-sess-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    fs.mkdirSync(app.sessionsDir, { recursive: true });
    fs.mkdirSync(app.workDir, { recursive: true });
    app.subscriptions = { codex: { installed: true, authenticated: true, runtime_status: 'ready' },
                          claude: { installed: false, authenticated: false, runtime_status: 'unavailable' } };
    app.activeProvider = 'codex';
    // A lane that fails, exactly like the quota-blocked codex lane on 2026-08-05.
    app.runLane = async () => ({ ok: false, provider: 'codex', content: '', error: 'quota blocked' });

    const frames = [];
    await app.chat({ text: 'first' }, (f) => frames.push(f));
    const startFrame = frames.find((f) => f.event === 'start');
    const sessionId = startFrame.data.session_id;
    // The turn failed, but the session it announced must EXIST - otherwise the id the
    // renderer now holds points at a file that was never written.
    assert.ok(fs.existsSync(app.sessionPath(sessionId)), 'a failed turn must still persist its session');

    // And a session id whose file has gone must not wedge every later message.
    fs.rmSync(app.sessionPath(sessionId));
    const second = [];
    const result = await app.chat({ text: 'second', session_id: sessionId }, (f) => second.push(f));
    assert.equal(result.ok, true, 'a missing session file must not become a 404 answer');
    assert.ok(second.some((f) => f.event === 'phase' && /previous session file was missing/.test(f.data.text)),
      'the recovery must be stated, not silent');

    // A malformed id is still refused.
    const bad = await app.chat({ text: 'third', session_id: '../escape' }, () => {});
    assert.equal(bad.ok, false);
    assert.equal(bad.status, 400);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('the default "Best" mode has a real council route in the packaged build', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-council-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    fs.mkdirSync(app.sessionsDir, { recursive: true });
    fs.mkdirSync(app.workDir, { recursive: true });
    app.subscriptions = { codex: { installed: true, authenticated: true, runtime_status: 'ready' },
                          claude: { installed: true, authenticated: true, runtime_status: 'ready' } };
    // A fresh install opens on Mode: Best, which routes to `council`. Before this the
    // very first message answered "provider unavailable: council".
    assert.ok(app.readyProviders().has('council'), 'council must be routable with two ready lanes');

    const seen = [];
    app.runLane = async (lane, prompt) => {
      seen.push(lane);
      return { ok: true, provider: lane, content: `answer from ${lane}`, error: '' };
    };
    const frames = [];
    const result = await app.chat({ text: 'hello', provider: 'council' }, (f) => frames.push(f));
    assert.equal(result.ok, true);
    assert.deepEqual(seen.slice(0, 2), ['claude', 'codex'], 'every ready lane is consulted');
    assert.ok(frames.some((f) => f.event === 'phase' && /merging 2 answers/.test(f.data.text)));

    // With only ONE lane alive the council must not pretend it merged anything.
    const single = new portable.PortableRuntime({ dataDir: temp });
    single.subscriptions = app.subscriptions;
    single.runLane = async (lane) => lane === 'codex'
      ? { ok: true, provider: lane, content: 'only me', error: '' }
      : { ok: false, provider: lane, content: '', error: 'quota blocked' };
    const soloFrames = [];
    await single.chat({ text: 'hello', provider: 'council' }, (f) => soloFrames.push(f));
    assert.ok(soloFrames.some((f) => f.event === 'phase' && /only one lane answered/.test(f.data.text)));

    // And when nothing answers, the failure names each lane's real reason.
    const dead = new portable.PortableRuntime({ dataDir: temp });
    dead.subscriptions = app.subscriptions;
    dead.runLane = async (lane) => ({ ok: false, provider: lane, content: '', error: 'quota blocked' });
    const deadFrames = [];
    await dead.chat({ text: 'hello', provider: 'council' }, (f) => deadFrames.push(f));
    const err = deadFrames.find((f) => f.event === 'error');
    assert.match(err.data.error, /no council lane answered/);
    assert.match(err.data.error, /quota blocked/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a response mode never overrides the only model this machine has', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-solo-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    fs.mkdirSync(app.sessionsDir, { recursive: true });
    fs.mkdirSync(app.workDir, { recursive: true });
    // Exactly ONE usable lane, which is the common case on a fresh machine.
    app.subscriptions = { codex: { installed: true, authenticated: true, runtime_status: 'ready' },
                          claude: { installed: false, authenticated: false, runtime_status: 'unavailable' } };
    assert.equal(app.readyProviders().has('council'), false, 'one lane cannot be a council');

    const used = [];
    app.runLane = async (lane) => { used.push(lane); return { ok: true, provider: lane, content: 'answered', error: '' }; };
    const frames = [];
    // The DEFAULT mode still asks for `council`; it must answer, not refuse.
    const result = await app.chat({ text: 'hello', provider: 'council' }, (f) => frames.push(f));
    assert.equal(result.ok, true);
    assert.deepEqual(used, ['codex'], 'the single available model answers');
    const done = frames.find((f) => f.event === 'done');
    assert.equal(done.data.provider, 'codex', 'the answer names the lane that really ran');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a machine with nothing signed in says what to do instead of "provider unavailable"', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-bare-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    fs.mkdirSync(app.sessionsDir, { recursive: true });
    // Exactly what a fresh install on a second computer looks like: no CLI, no key.
    app.subscriptions = { codex: { installed: false, authenticated: false, runtime_status: 'unavailable' },
                          claude: { installed: false, authenticated: false, runtime_status: 'unavailable' } };
    const result = await app.chat({ text: 'hello', provider: 'council' }, () => {});
    assert.equal(result.ok, false);
    assert.match(result.error, /No model is ready on this PC/);
    assert.match(result.error, /add an API key/);
    assert.doesNotMatch(result.error, /provider unavailable/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('an empty machine is "no model", not "sidecar down"', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-health-'));
  try {
    const app = new portable.PortableRuntime({ dataDir: temp });
    app.subscriptions = { codex: { installed: false, authenticated: false, runtime_status: 'unavailable' },
                          claude: { installed: false, authenticated: false, runtime_status: 'unavailable' } };
    const health = app.health();
    // The backend IS answering; it just has nothing signed in. Reporting ok=false made
    // the titlebar say "sidecar down" on a fresh machine, which reads as a broken app.
    assert.equal(health.ok, true, 'a running backend with no models is still healthy');
    assert.equal(health.models_ready, false, 'and it must say plainly that no model is ready');
    assert.equal(health.ready_lanes, 0);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
