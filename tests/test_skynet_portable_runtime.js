'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const test = require('node:test');

const {
  PortableRuntime,
  cliSignature,
  extractGeminiAnswer,
  extractProviderError,
  providerCommand,
  resolveCliCommand,
  validateOrchestration,
} = require('../desktop/lib/portable_runtime');

test('portable commands use local subscription CLIs without token paths or write-capable tools', () => {
  const workDir = 'C:\\portable\\workspace';
  const outputFile = 'C:\\portable\\last.txt';
  const codex = providerCommand('codex', { workDir, outputFile });
  assert.equal(codex.command, 'codex');
  assert.ok(codex.args.includes('--sandbox'));
  assert.ok(codex.args.includes('read-only'));
  assert.ok(codex.args.includes('--ephemeral'));
  assert.ok(codex.args.includes('--ignore-user-config'));
  assert.ok(codex.args.includes('--ignore-rules'));
  assert.ok(codex.args.includes('approval_policy="never"'));
  assert.equal(codex.args.some((arg) => /auth\.json|CODEX_HOME/i.test(arg)), false);

  const claude = providerCommand('claude', { workDir, outputFile });
  assert.equal(claude.command, 'claude');
  assert.deepEqual(claude.args.slice(-4), ['--tools', '', '--permission-mode', 'plan']);
  assert.ok(claude.args.includes('--no-session-persistence'));
  assert.ok(claude.args.includes('--safe-mode'));
});

test('role validator enforces one orchestrator and distinct authenticated workers', () => {
  const ready = new Set(['codex', 'claude']);
  // A role is a ROW, not a bare lane id: the same lane can appear twice with different
  // models, so every role normalizes to {lane, model} before it is validated.
  assert.deepEqual(validateOrchestration({ enabled: true, orchestrator: 'codex', workers: ['claude'] }, ready), {
    enabled: true,
    orchestrator: { lane: 'codex', model: '' },
    workers: [{ lane: 'claude', model: '' }],
    advisors: [],
  });
  // Repeats are deliberately allowed — two workers on one lane is an ordinary fan-out,
  // and refusing it was the wall the owner hit. What stays refused is a lane that is not
  // authenticated, because that is a fleet that cannot run.
  assert.deepEqual(
    validateOrchestration({ enabled: true, orchestrator: 'codex', workers: ['codex'] }, ready).workers,
    [{ lane: 'codex', model: '' }],
  );
  assert.throws(() => validateOrchestration({ enabled: true, orchestrator: 'codex', workers: ['gemini'] }, ready), /not an authenticated lane/);
  assert.throws(() => validateOrchestration({ enabled: true, orchestrator: 'codex', workers: [] }, ready), /at least one/);
});

test('provider failures expose only bounded structured diagnostics', () => {
  assert.equal(
    extractProviderError('claude', JSON.stringify({ subtype: 'error_max_turns', message: 'bounded detail' }), '', 1, null),
    'error_max_turns: bounded detail',
  );
  assert.equal(
    extractProviderError('claude', JSON.stringify({ is_error: true, api_error_status: 429, result: 'weekly limit' }), '', 1, null),
    'rate_limited (HTTP 429): weekly limit',
  );
  assert.equal(extractProviderError('claude', JSON.stringify({ email: 'secret@example.test' }), '', 1, null), 'provider exited code=1 signal=');
});

test('Windows npm shims resolve to direct executables without cmd shell interpolation', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-cli-resolve-'));
  const nodeDir = path.join(temp, 'node-bin');
  const npmDir = path.join(temp, 'npm-bin');
  try {
    fs.mkdirSync(nodeDir, { recursive: true });
    fs.mkdirSync(path.join(npmDir, 'node_modules', '@openai', 'codex', 'bin'), { recursive: true });
    fs.mkdirSync(path.join(npmDir, 'node_modules', '@anthropic-ai', 'claude-code', 'bin'), { recursive: true });
    fs.writeFileSync(path.join(nodeDir, 'node.exe'), 'fixture');
    fs.writeFileSync(path.join(npmDir, 'codex.cmd'), 'fixture');
    fs.writeFileSync(path.join(npmDir, 'node_modules', '@openai', 'codex', 'bin', 'codex.js'), 'fixture');
    fs.writeFileSync(path.join(npmDir, 'claude.cmd'), 'fixture');
    fs.writeFileSync(path.join(npmDir, 'node_modules', '@anthropic-ai', 'claude-code', 'bin', 'claude.exe'), 'fixture');
    const pathValue = [npmDir, nodeDir].join(path.delimiter);
    const codex = resolveCliCommand('codex', { fs, platform: 'win32', pathValue });
    const claude = resolveCliCommand('claude', { fs, platform: 'win32', pathValue });
    assert.equal(codex.command, path.join(nodeDir, 'node.exe'));
    assert.deepEqual(codex.prefixArgs, [path.join(npmDir, 'node_modules', '@openai', 'codex', 'bin', 'codex.js')]);
    assert.equal(claude.command, path.join(npmDir, 'node_modules', '@anthropic-ai', 'claude-code', 'bin', 'claude.exe'));
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('portable orchestration calls ordered worker then exact orchestrator and persists only app sessions', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-portable-test-'));
  const calls = [];
  let nextPid = 9000;
  const spawnSync = (command, args) => {
    if (command === 'codex' && args[0] === 'login') return { status: 0, stdout: 'Logged in using ChatGPT', stderr: '' };
    if (command === 'claude' && args[0] === 'auth') return { status: 0, stdout: JSON.stringify({ loggedIn: true, subscriptionType: 'pro', email: 'must-not-leak@example.test' }), stderr: '' };
    if (command === 'tasklist') return { status: 0, stdout: '' };
    return { status: 0, stdout: '', stderr: '' };
  };
  const spawn = (command, args) => {
    calls.push({ command, args: args.slice() });
    const child = new EventEmitter();
    child.pid = nextPid += 1;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.kill = () => true;
    child.stdin.on('data', () => {});
    child.stdin.on('finish', () => {
      setImmediate(() => {
        if (command === 'codex') {
          const at = args.indexOf('--output-last-message');
          fs.writeFileSync(args[at + 1], 'FINAL FROM CODEX', 'utf8');
          child.stdout.end('{"type":"turn.completed"}\n');
        } else {
          child.stdout.end(JSON.stringify({ result: 'WORKER FROM CLAUDE' }));
        }
        child.stderr.end();
        child.emit('close', 0, null);
      });
    });
    return child;
  };

  try {
    const runtime = new PortableRuntime({
      dataDir: temp,
      spawn,
      spawnSync,
      platform: 'win32',
      commands: {
        codex: { command: 'codex', prefixArgs: [] },
        claude: { command: 'claude', prefixArgs: [] },
      },
    });
    const health = runtime.start();
    assert.equal(health.authenticated_lanes, 2);
    assert.equal(JSON.stringify(runtime.laneRows()).includes('must-not-leak'), false);
    const frames = [];
    const result = await runtime.chat({
      text: 'owner request',
      orchestration: { enabled: true, orchestrator: 'codex', workers: ['claude'] },
    }, (frame) => frames.push(frame));
    assert.equal(result.ok, true);
    assert.deepEqual(calls.map((call) => call.command), ['claude', 'codex']);
    assert.equal(frames.filter((frame) => frame.event === 'delta').map((frame) => frame.data.text).join(''), 'FINAL FROM CODEX');
    assert.equal(frames.some((frame) => JSON.stringify(frame).includes('must-not-leak')), false);
    assert.equal(runtime.listSessions(10).length, 1);
    assert.equal(fs.existsSync(path.join(temp, 'settings.json')), false);
    assert.equal(runtime.stop().ok, true);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('provider timeout settles at the deadline even when process containment fails', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-portable-timeout-'));
  let child;
  let containmentCalls = 0;
  const spawn = () => {
    child = new EventEmitter();
    child.pid = 9100;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.kill = () => false;
    return child;
  };
  const spawnSync = (command) => {
    containmentCalls += 1;
    if (command === 'tasklist') return { status: 0, stdout: '"node.exe","9100"' };
    if (command === 'taskkill') {
      const until = Date.now() + 150;
      while (Date.now() < until) { /* prove slow containment cannot delay settlement */ }
      return { status: 1, stdout: '', stderr: 'access denied', error: new Error('access denied') };
    }
    return { status: 1, stdout: '', stderr: '' };
  };

  try {
    const runtime = new PortableRuntime({
      dataDir: temp,
      spawn,
      spawnSync,
      platform: 'win32',
      providerTimeoutMs: 20,
      commands: { codex: { command: 'codex', prefixArgs: [] } },
    });
    fs.mkdirSync(runtime.tmpDir, { recursive: true });
    const result = await Promise.race([
      runtime.runProvider('codex', 'bounded request'),
      new Promise((_, reject) => setTimeout(() => reject(new Error('provider promise exceeded hard deadline')), 500)),
    ]);
    assert.equal(result.ok, false);
    assert.equal(result.timed_out, true);
    assert.match(result.error, /time limit reached; containment scheduled/);
    assert.equal(containmentCalls, 0);
    assert.equal(runtime.activeChildren.has(child), true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(containmentCalls > 0);
    assert.equal(runtime.activeChildren.has(child), true);
    child.emit('close', 1, 'SIGKILL');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(runtime.activeChildren.has(child), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('provider timeout retains a live child when the Windows liveness probe is unknown', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-portable-unknown-liveness-'));
  let child;
  let alive = true;
  let tasklistCalls = 0;
  let taskkillCalls = 0;
  const spawn = () => {
    child = new EventEmitter();
    child.pid = 9200;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.kill = () => false;
    return child;
  };
  const spawnSync = (command) => {
    if (command === 'tasklist') {
      tasklistCalls += 1;
      if (tasklistCalls === 1) {
        return { status: 1, stdout: '', stderr: 'probe denied', error: new Error('probe denied') };
      }
      return { status: 0, stdout: alive ? '"node.exe","9200"' : '', stderr: '' };
    }
    if (command === 'taskkill') {
      taskkillCalls += 1;
      alive = false;
      return { status: 0, stdout: '', stderr: '' };
    }
    return { status: 1, stdout: '', stderr: '' };
  };

  try {
    const runtime = new PortableRuntime({
      dataDir: temp,
      spawn,
      spawnSync,
      platform: 'win32',
      providerTimeoutMs: 20,
      commands: { codex: { command: 'codex', prefixArgs: [] } },
    });
    fs.mkdirSync(runtime.tmpDir, { recursive: true });
    const result = await runtime.runProvider('codex', 'bounded request');
    assert.equal(result.ok, false);
    assert.equal(result.timed_out, true);
    assert.equal(runtime.activeChildren.has(child), true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(tasklistCalls, 1);
    assert.equal(taskkillCalls, 0);
    assert.equal(runtime.activeChildren.has(child), true);

    const stopped = runtime.stop();
    assert.equal(stopped.ok, true);
    assert.equal(taskkillCalls, 1);
    assert.equal(alive, false);
    assert.equal(runtime.activeChildren.has(child), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('cli signature tracks the files a CLI login writes, and records absence as its own state', () => {
  const present = new Map();
  const fakeFs = Object.create(fs);
  fakeFs.statSync = (target) => {
    const key = String(target);
    if (present.has(key)) return present.get(key);
    const err = new Error(`ENOENT: ${key}`);
    err.code = 'ENOENT';
    throw err;
  };
  const commands = { codex: { command: 'codex.exe' }, claude: { command: 'claude.exe' } };

  const loggedOut = cliSignature(fakeFs, commands);
  assert.match(loggedOut, /\.credentials\.json:absent/);

  const credentials = path.join(os.homedir(), '.claude', '.credentials.json');
  present.set(credentials, { size: 512, mtimeMs: 1000 });
  const loggedIn = cliSignature(fakeFs, commands);
  assert.notEqual(loggedIn, loggedOut, 'a fresh login must change the signature');

  present.set(credentials, { size: 512, mtimeMs: 2000 });
  assert.notEqual(cliSignature(fakeFs, commands), loggedIn, 'a token refresh must change the signature');

  // A CLI that is not installed yet must not read the same as one that is.
  assert.notEqual(
    cliSignature(fakeFs, { codex: commands.codex, claude: null }),
    loggedIn,
  );

  // Ordinary Claude Code use rewrites ~/.claude.json constantly. If that file were part
  // of the signature, every poll would spend ~600ms spawning CLIs while the owner works.
  const settled = cliSignature(fakeFs, commands);
  const busyStateFile = path.join(os.homedir(), '.claude.json');
  present.set(busyStateFile, { size: 99, mtimeMs: 4242 });
  assert.equal(cliSignature(fakeFs, commands), settled,
    'unrelated CLI state churn must not force a re-probe');
});

test('a CLI signed into while the app is open goes ready without a restart, and idle polls do not re-probe', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-portable-detect-'));
  try {
    const credentials = path.join(os.homedir(), '.claude', '.credentials.json');
    const disk = new Map([[credentials, { size: 10, mtimeMs: 1 }]]);
    let claudeLoggedIn = false;
    let claudeProbes = 0;

    const fakeFs = Object.create(fs);
    fakeFs.statSync = (target, ...rest) => {
      const key = String(target);
      if (disk.has(key)) return disk.get(key);
      if (key === credentials) {
        const err = new Error('ENOENT');
        err.code = 'ENOENT';
        throw err;
      }
      return fs.statSync(target, ...rest);
    };

    const spawnSync = (command, args) => {
      if (command === 'claude.exe') {
        claudeProbes += 1;
        return claudeLoggedIn
          ? { status: 0, stdout: JSON.stringify({ loggedIn: true, subscriptionType: 'pro', email: 'must-not-leak@example.test' }), stderr: '' }
          : { status: 1, stdout: '', stderr: 'Not logged in' };
      }
      if (command === 'codex.exe') return { status: 1, stdout: '', stderr: 'Not logged in' };
      return { status: 0, stdout: '', stderr: '' };
    };

    const runtime = new PortableRuntime({
      dataDir: temp,
      fs: fakeFs,
      spawnSync,
      platform: 'win32',
      commands: {
        codex: { command: 'codex.exe', prefixArgs: [] },
        claude: { command: 'claude.exe', prefixArgs: [] },
      },
    });

    // Boot with nothing signed in — the state the owner's app was actually in.
    runtime.start();
    assert.equal(runtime.subscriptions.claude.authenticated, false);
    assert.equal(runtime.activeProvider, null);
    assert.equal(claudeProbes, 1);

    // Polling an unchanged machine must not spawn CLI probes over and over.
    await runtime.api('GET', '/lanes');
    await runtime.api('GET', '/health');
    assert.equal(claudeProbes, 1, 'unchanged disk state must not trigger a re-probe');

    // The owner signs in to the Claude CLI while the app keeps running.
    claudeLoggedIn = true;
    disk.set(credentials, { size: 640, mtimeMs: 2 });

    const lanes = await runtime.api('GET', '/lanes');
    const claude = lanes.data.lanes.find((lane) => lane.id === 'claude');
    assert.equal(claudeProbes, 2, 'a new login must trigger exactly one re-probe');
    assert.equal(claude.status, 'ready');
    assert.equal(claude.can_orchestrate, true);
    assert.equal(claude.detail, 'pro subscription ready');
    assert.equal(/must-not-leak/.test(JSON.stringify(lanes.data)), false);
    assert.equal(runtime.activeProvider, 'claude', 'the newly ready lane must become answerable');
    assert.equal(lanes.data.active, 'claude');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('all three CLI lanes detect, and a keyring login outranks a stale credential file', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-three-lane-'));
  try {
    const credentials = path.join(os.homedir(), '.gemini', 'oauth_creds.json');
    // A months-old file left next to a CURRENT keyring login. Reading the file first
    // made a perfectly good Gemini session report itself as expired.
    const staleFile = JSON.stringify({ refresh_token: 'stale', expiry_date: 1 });
    let keyringHasGemini = true;

    const fakeFs = Object.create(fs);
    fakeFs.readFileSync = (target, ...rest) => {
      if (String(target) === credentials) return staleFile;
      return fs.readFileSync(target, ...rest);
    };
    fakeFs.statSync = (target, ...rest) => {
      if (String(target) === credentials) return { size: 64, mtimeMs: 5 };
      return fs.statSync(target, ...rest);
    };

    const spawnSync = (command, args) => {
      if (command === 'cmdkey.exe') {
        const target = String(args[0] || '').replace('/list:', '');
        return keyringHasGemini && target === 'gemini:antigravity'
          ? { status: 0, stdout: `\n    Target: ${target}\n    Type: Generic\n`, stderr: '' }
          : { status: 0, stdout: '\n* NONE *\n', stderr: '' };
      }
      if (command === 'codex.exe') return { status: 0, stdout: 'Logged in', stderr: '' };
      if (command === 'claude.exe') {
        return { status: 0, stdout: JSON.stringify({ loggedIn: true, subscriptionType: 'pro' }), stderr: '' };
      }
      if (command === 'agy.exe') return { status: 0, stdout: '1.1.9', stderr: '' };
      return { status: 0, stdout: '', stderr: '' };
    };

    const commands = {
      codex: { command: 'codex.exe', prefixArgs: [] },
      claude: { command: 'claude.exe', prefixArgs: [] },
      gemini: { command: 'agy.exe', prefixArgs: [] },
    };
    const runtime = new PortableRuntime({
      dataDir: temp, fs: fakeFs, spawnSync, platform: 'win32', commands,
    });
    runtime.start();

    const lanes = (await runtime.api('GET', '/lanes')).data.lanes;
    const byId = Object.fromEntries(lanes.map((lane) => [lane.id, lane]));
    for (const id of ['codex', 'claude', 'gemini']) {
      assert.equal(byId[id].status, 'ready', `${id} must be ready`);
      assert.equal(byId[id].can_orchestrate, true, `${id} must be able to answer`);
    }
    assert.equal(byId.gemini.label, 'Gemini');
    // The keyring won, so the lane must NOT be described from the stale expired file.
    assert.equal(byId.gemini.detail, 'local subscription login ready');

    // Signing out of the keyring must fall back to the file, which IS expired.
    keyringHasGemini = false;
    runtime.refreshSubscriptions({ force: true });
    assert.match(runtime.subscriptions.gemini.detail, /expired/);
    assert.equal(runtime.subscriptions.gemini.authenticated, true);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('the gemini lane passes its prompt as the --print value, never piped or pre-flag', () => {
  const spec = providerCommand('gemini', {
    workDir: 'C:\w', outputFile: 'C:\w\out.txt', model: 'gemini-3-pro', prompt: 'ask me',
  }, { gemini: { command: 'agy.exe', prefixArgs: [] } });
  assert.equal(spec.command, 'agy.exe');
  // --print takes the prompt as its VALUE, so it must be last; any flag after it would be
  // swallowed into the question instead of parsed.
  assert.deepEqual(spec.args.slice(-2), ['--print', 'ask me']);
  assert.ok(spec.args.indexOf('--output-format') < spec.args.indexOf('--print'));
  assert.ok(spec.args.includes('--mode') && spec.args.includes('plan'));
  assert.equal(extractGeminiAnswer(JSON.stringify({ status: 'SUCCESS', response: 'hello\n' })), 'hello\n');
  assert.equal(extractGeminiAnswer(JSON.stringify({ status: 'ERROR', response: 'nope' })), '');
});
