'use strict';

const path = require('path');

function parseSseFrame(raw) {
  let event = 'message';
  const dataLines = [];
  for (const sourceLine of String(raw || '').split('\n')) {
    const line = sourceLine.replace(/\r$/, '');
    if (!line || line.startsWith(':')) continue;
    const cut = line.indexOf(':');
    const field = cut === -1 ? line : line.slice(0, cut);
    let value = cut === -1 ? '' : line.slice(cut + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') event = value;
    else if (field === 'data') dataLines.push(value);
  }
  const rawData = dataLines.join('\n');
  let data = {};
  if (rawData) {
    try { data = JSON.parse(rawData); } catch (_) { data = { text: rawData }; }
  }
  return { event, data, raw: rawData };
}

function createSseDecoder(onFrame, maxBytes) {
  let buffer = '';
  let size = 0;
  const limit = Number(maxBytes) || (8 << 20);
  function emit(raw) {
    if (String(raw).trim()) onFrame(parseSseFrame(raw));
  }
  return {
    push(chunk) {
      size += Buffer.byteLength(chunk);
      if (size > limit) throw new Error('sidecar chat stream exceeded limit');
      // Normalize after appending so a CRLF split across two TCP chunks is still
      // recognized as one line ending. Per-chunk normalization merges SSE frames.
      buffer += String(chunk);
      buffer = buffer.replace(/\r\n/g, '\n');
      let cut = buffer.indexOf('\n\n');
      while (cut !== -1) {
        emit(buffer.slice(0, cut));
        buffer = buffer.slice(cut + 2);
        cut = buffer.indexOf('\n\n');
      }
    },
    end() {
      if (buffer.trim()) emit(buffer);
      buffer = '';
    },
    bytes() { return size; },
  };
}

function isTrustedRenderer(windowRef, event) {
  return Boolean(
    windowRef &&
    !windowRef.isDestroyed() &&
    event &&
    event.sender === windowRef.webContents
  );
}

function discoverRepoRoot(options) {
  const opts = options || {};
  const fs = opts.fs;
  const dirname = opts.dirname || __dirname;
  const candidates = [];
  if (opts.envRoot) candidates.push(opts.envRoot);
  candidates.push(path.resolve(dirname, '..'));
  for (const candidate of candidates) {
    const root = path.resolve(String(candidate || ''));
    if (fs.existsSync(path.join(root, 'tools', 'skynet_app_server.py'))) return root;
  }
  return null;
}

function probeProcessState(pid, platform, killFn, spawnSync) {
  if (!Number.isInteger(pid) || pid <= 0) {
    return { state: 'absent', method: 'invalid_pid', status: null, error: '' };
  }
  if (platform === 'win32' && typeof spawnSync === 'function') {
    let probe;
    try {
      probe = spawnSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], {
        encoding: 'utf8', windowsHide: true, timeout: 10000,
      });
    } catch (err) {
      return { state: 'unknown', method: 'tasklist', status: null, error: String(err && (err.message || err) || 'tasklist threw') };
    }
    if (!probe || probe.error || probe.status !== 0) {
      return {
        state: 'unknown',
        method: 'tasklist',
        status: probe && Number.isInteger(probe.status) ? probe.status : null,
        error: probe && probe.error ? String(probe.error.message || probe.error) : 'tasklist probe failed',
      };
    }
    return {
      state: String(probe.stdout || '').includes(`"${pid}"`) ? 'alive' : 'absent',
      method: 'tasklist',
      status: probe.status,
      error: '',
    };
  }
  try {
    killFn(pid, 0);
    return { state: 'alive', method: 'signal_zero', status: null, error: '' };
  } catch (err) {
    if (err && err.code === 'ESRCH') return { state: 'absent', method: 'signal_zero', status: null, error: '' };
    if (err && err.code === 'EPERM') return { state: 'alive', method: 'signal_zero', status: null, error: '' };
    return { state: 'unknown', method: 'signal_zero', status: null, error: String(err && (err.message || err) || 'liveness probe failed') };
  }
}

// Retained as a compatibility helper for callers that need a conservative
// boolean. Containment uses probeProcessState directly so UNKNOWN is never
// credited as process death.
function processExists(pid, platform, killFn, spawnSync) {
  return probeProcessState(pid, platform, killFn, spawnSync).state === 'alive';
}

function terminateProcessTree(child, dependencies) {
  const deps = dependencies || {};
  const platform = deps.platform || process.platform;
  const spawnSync = deps.spawnSync;
  const killFn = deps.killFn || process.kill.bind(process);
  const pid = child && Number(child.pid);
  if (!Number.isInteger(pid) || pid <= 0) {
    return { ok: true, pid: null, method: 'no_process' };
  }
  const initial = probeProcessState(pid, platform, killFn, spawnSync);
  if (initial.state === 'absent') {
    return { ok: true, pid, method: 'already_exited' };
  }
  if (initial.state === 'unknown') {
    return {
      ok: false,
      pid,
      method: 'liveness_unknown',
      command_status: null,
      command_error: initial.error,
      command_ok: false,
      alive_after: null,
      probe_state: initial.state,
    };
  }

  let commandResult = null;
  if (platform === 'win32') {
    try {
      commandResult = spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], {
        encoding: 'utf8', windowsHide: true, timeout: 15000,
      });
    } catch (err) {
      commandResult = { status: null, error: err };
    }
  } else {
    try { killFn(-pid, 'SIGTERM'); } catch (_) {
      try { child.kill('SIGTERM'); } catch (_) { /* verify below */ }
    }
  }

  const afterCommand = probeProcessState(pid, platform, killFn, spawnSync);
  if (afterCommand.state !== 'absent') {
    try { child.kill('SIGKILL'); } catch (_) { /* verify below */ }
  }
  const finalState = probeProcessState(pid, platform, killFn, spawnSync);
  const commandOk = !commandResult || (commandResult.status === 0 && !commandResult.error);
  return {
    ok: finalState.state === 'absent',
    pid,
    method: platform === 'win32' ? 'taskkill_tree' : 'process_group',
    command_status: commandResult ? commandResult.status : null,
    command_error: commandResult && commandResult.error ? String(commandResult.error.message || commandResult.error) : '',
    command_ok: commandOk,
    alive_after: finalState.state === 'unknown' ? null : finalState.state === 'alive',
    probe_state: finalState.state,
    probe_error: finalState.error,
  };
}

module.exports = {
  createSseDecoder,
  discoverRepoRoot,
  isTrustedRenderer,
  parseSseFrame,
  probeProcessState,
  processExists,
  terminateProcessTree,
};
