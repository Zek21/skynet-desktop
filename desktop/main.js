/**
 * Skynet desktop app — Electron main process.
 *
 * Why this exists (2026-08-04): the owner asked several times for the Skynet *app*,
 * pointing at Anthropic's Claude desktop app on his screen, and kept being handed a
 * terminal REPL or a browser tab on Mission Control. Neither is an application.
 *
 * Inspecting the bar settles the architecture: Claude's claude.exe ships
 * chrome_100_percent.pak / v8_context_snapshot.bin / LICENSES.chromium.html and its
 * window class is Chrome_WidgetWin_1 — it is Chromium rendering a web UI, packaged as
 * a binary the vendor owns. So matching it needs the same SHAPE, not native widgets:
 * this main process owns a frameless Chromium window, and spawns Skynet's Python
 * sidecar as a child process that carries the real answer lanes.
 *
 * Fail-closed on purpose: we do NOT open a window onto a dead backend. A blank cockpit
 * reads as "the fleet is idle" when the truth is "the fleet is unreachable" — so the
 * sidecar must handshake its port+token on stdout before any window is created, and if
 * it doesn't we show the real error instead of an empty chat.
 */

'use strict';

const { app, BrowserWindow, ipcMain, Menu, shell, dialog, session } = require('electron');
const { spawn, spawnSync } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');
const {
  createSseDecoder,
  discoverRepoRoot,
  isTrustedRenderer,
  terminateProcessTree,
} = require('./lib/sidecar_runtime');
const { PortableRuntime } = require('./lib/portable_runtime');

// A distributed installer must be self-contained and must never execute a mutable
// repository merely because one happens to exist at a path baked on the build host.
// Repository discovery is a development-only convenience; packaged builds always use
// the bundled portable runtime and the subscriptions already logged in on that PC.
const REPO_ROOT = app.isPackaged ? null : discoverRepoRoot({
  fs,
  dirname: __dirname,
  envRoot: process.env.SKYNET_REPO_ROOT,
});
const SERVER_SCRIPT = REPO_ROOT ? path.join(REPO_ROOT, 'tools', 'skynet_app_server.py') : null;

// Which BYTES is this? Two payloads once shipped as "0.1.1" (app.asar c13382ec vs 6bf1ba06,
// built 2h46m apart), so a crash report naming the version could not be mapped to code.
// tools/skynet_desktop_build_stamp.py injects this via electron-builder --extraMetadata, so it
// lives in the app.asar's own package.json and is recoverable from the artifact alone. An
// unstamped dev run has no metadata and must SAY so rather than imply a released build.
const BUILD_STAMP = (() => {
  try {
    const meta = require('./package.json');
    const stamp = meta && meta.skynetBuild;
    if (stamp && typeof stamp.buildId === 'string' && stamp.buildId) {
      return {
        buildId: stamp.buildId,
        sourceDigest: String(stamp.sourceDigest || ''),
        sourceCommit: String(stamp.sourceCommit || ''),
        // extraMetadata arrives over a CLI string, so 'false' is a truthy string. Compare
        // explicitly -- a coerced Boolean('false') would report a dirty build as clean.
        sourceMembersClean: stamp.sourceMembersClean === true || stamp.sourceMembersClean === 'true',
      };
    }
  } catch (_) { /* unpackaged dev run: fall through to the unstamped answer */ }
  return { buildId: '', sourceDigest: '', sourceCommit: '', sourceMembersClean: false };
})();
const HANDSHAKE_PREFIX = 'SKYNET_APP_SERVER ';
const HANDSHAKE_TIMEOUT_MS = 30000;
const TURN_TIMEOUT_SECONDS = 15 * 60;
const TURN_TIMEOUT_MS = (TURN_TIMEOUT_SECONDS * 1000) + 10000;
const MAX_SIDECAR_RESPONSE_BYTES = 8 << 20;
const JSON_ROUTES = new Map([
  ['GET /health', true],
  ['GET /lanes', true],
  ['GET /models', true],
  ['GET /sessions', true],
  ['GET /session', true],
  ['GET /workspace', true],
  ['POST /provider', true],
  ['POST /workspace', true],
  // BYOK: the renderer may ASK the sidecar to store, test, retarget or delete a key.
  // It never receives one back -- /models and these routes return a masked hint only.
  ['POST /apikeys', true],
  ['POST /apikeys/test', true],
  ['POST /apikeys/model', true],
  ['POST /apikeys/remove', true],
  // Finding — or installing — the agent CLIs on a machine that is not the build host.
  // The renderer may ASK for a rescan or an install; it never gets a path to execute.
  ['POST /cli/rescan', true],
  ['POST /cli/install', true],
]);

// Claude's window measured 1216x808 on this machine. The cockpit carries a lane picker
// and a live thinking panel per turn, so it opens a little larger rather than matching.
const WIN_WIDTH = 1440;
const WIN_HEIGHT = 920;
const MIN_WIDTH = 900;
const MIN_HEIGHT = 600;
const BG = '#0A0E14';

/** @type {{port:number, token:string, pid:number}|null} */
let handshake = null;
/** @type {import('child_process').ChildProcess|null} */
let sidecar = null;
let lastSidecarExit = null;
/** @type {BrowserWindow|null} */
let win = null;
let sidecarStderr = '';
let quitting = false;
let quitCleanupComplete = false;
let restartPromise = null;
let portableRuntime = null;
let backendKind = REPO_ROOT ? 'repo' : 'portable';

/**
 * Find a usable Python. `python` on Windows can be the Microsoft Store alias stub,
 * which exits 9009 and prints nothing — so we probe candidates rather than trusting
 * the first name on PATH.
 */
function resolvePython() {
  const candidates = [];
  if (process.env.SKYNET_PYTHON) candidates.push(process.env.SKYNET_PYTHON);
  candidates.push('python', 'python3', 'py');
  for (const cmd of candidates) {
    try {
      const probe = spawnSync(cmd, ['-c', 'import sys; print(sys.version_info[0])'], {
        encoding: 'utf8',
        timeout: 10000,
        windowsHide: true,
      });
      if (probe.status === 0 && String(probe.stdout).trim().startsWith('3')) return cmd;
    } catch (_) {
      /* try the next candidate */
    }
  }
  return null;
}

/**
 * Start the sidecar and resolve once it prints its handshake line. Rejects with the
 * real reason (missing python, missing script, early exit + stderr, timeout) so the
 * failure dialog can name the actual cause instead of "something went wrong".
 */
function startSidecar() {
  return new Promise((resolve, reject) => {
    if (!SERVER_SCRIPT || !fs.existsSync(SERVER_SCRIPT)) {
      reject(new Error(`sidecar missing: ${SERVER_SCRIPT}`));
      return;
    }
    const python = resolvePython();
    if (!python) {
      reject(new Error('no working Python 3 found (set SKYNET_PYTHON to the interpreter path)'));
      return;
    }

    sidecarStderr = '';
    const child = spawn(python, [
      SERVER_SCRIPT,
      '--port', '0',
      '--turn-timeout', String(TURN_TIMEOUT_SECONDS),
    ], {
      cwd: REPO_ROOT,
      windowsHide: true,
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUNBUFFERED: '1' },
    });
    sidecar = child;

    let settled = false;
    let stdoutBuf = '';

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const cleanup = terminateProcessTree(child, { platform: process.platform, spawnSync });
      reject(new Error(`sidecar did not hand shake within ${HANDSHAKE_TIMEOUT_MS / 1000}s\n${sidecarStderr.slice(-2000)}`));
      if (!cleanup.ok) console.error('[sidecar] handshake-timeout cleanup failed', cleanup);
    }, HANDSHAKE_TIMEOUT_MS);

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdoutBuf += chunk;
      let nl;
      while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line.startsWith(HANDSHAKE_PREFIX)) {
          if (line) console.log('[sidecar]', line);
          continue;
        }
        if (settled) continue;
        try {
          const payload = JSON.parse(line.slice(HANDSHAKE_PREFIX.length));
          if (!payload.port || !payload.token) throw new Error('handshake missing port/token');
          if (process.platform === 'win32' && payload.process_tree_guard !== 'windows_job_object') {
            throw new Error('sidecar did not prove Windows Job Object containment');
          }
          settled = true;
          clearTimeout(timer);
          resolve(payload);
        } catch (err) {
          settled = true;
          clearTimeout(timer);
          reject(new Error(`unparsable handshake: ${err.message}\n${line.slice(0, 300)}`));
        }
      }
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      sidecarStderr += chunk;
      if (sidecarStderr.length > 20000) sidecarStderr = sidecarStderr.slice(-20000);
      console.error('[sidecar]', String(chunk).trimEnd());
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`could not start sidecar: ${err.message}`));
    });

    child.on('exit', (code, signal) => {
      const wasCurrent = sidecar === child;
      if (wasCurrent) {
        sidecar = null;
        handshake = null;
      }
      lastSidecarExit = { pid: child.pid, code, signal, at: new Date().toISOString() };
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`sidecar exited early (code=${code} signal=${signal})\n${sidecarStderr.slice(-2000)}`));
        return;
      }
      // Died after we were up: the app is now brainless, so say so rather than
      // leaving a chat box that silently fails on every send.
      if (!quitting && win && !win.isDestroyed()) {
        win.webContents.send('skynet:sidecar-down', {
          code,
          signal,
          reason: code === 124 ? 'turn_timeout' : 'backend_exited',
        });
      }
    });
  });
}

function startBackend() {
  if (REPO_ROOT) return startSidecar();
  portableRuntime = portableRuntime || new PortableRuntime({
    dataDir: path.join(app.getPath('userData'), 'portable-runtime'),
    spawn,
    spawnSync,
    platform: process.platform,
  });
  const health = portableRuntime.start();
  return Promise.resolve({
    port: 0,
    token: 'main-process-only-portable-runtime',
    pid: process.pid,
    runtime: health.runtime,
  });
}

/** Kill the whole sidecar tree and verify the root is gone before reporting success. */
function stopSidecar() {
  const child = sidecar;
  if (!child || child.pid === undefined) {
    sidecar = null;
    handshake = null;
    return { ok: true, method: 'no_process' };
  }
  const result = terminateProcessTree(child, { platform: process.platform, spawnSync });
  if (result.ok && sidecar === child) {
    sidecar = null;
    handshake = null;
  }
  return result;
}

function stopBackend() {
  if (backendKind === 'portable') {
    return portableRuntime ? portableRuntime.stop() : { ok: true, method: 'portable_not_started' };
  }
  return stopSidecar();
}

async function restartSidecar() {
  if (restartPromise) return restartPromise;
  restartPromise = (async () => {
    const stopped = stopSidecar();
    if (!stopped.ok) throw new Error(`could not contain previous sidecar pid ${stopped.pid}`);
    const next = await startSidecar();
    handshake = next;
    return { ok: true, backendReady: true, pid: next.pid };
  })();
  try {
    return await restartPromise;
  } finally {
    restartPromise = null;
  }
}

async function restartBackend() {
  if (restartPromise) return restartPromise;
  restartPromise = (async () => {
    const stopped = stopBackend();
    if (!stopped.ok) throw new Error('could not contain previous backend process tree');
    if (backendKind === 'portable') {
      const health = portableRuntime.start();
      return { ok: true, backendReady: health.ok, runtime: health.runtime };
    }
    const next = await startSidecar();
    handshake = next;
    return { ok: true, backendReady: true, pid: next.pid };
  })();
  try {
    return await restartPromise;
  } finally {
    restartPromise = null;
  }
}

function requireHandshake() {
  if (!handshake || !handshake.port || !handshake.token) {
    throw new Error('sidecar handshake unavailable');
  }
  return handshake;
}

function normalizeRoute(method, rawRoute) {
  const verb = String(method || 'GET').toUpperCase();
  const route = new URL(String(rawRoute || ''), 'http://127.0.0.1');
  const key = `${verb} ${route.pathname}`;
  if (!JSON_ROUTES.has(key)) throw new Error(`sidecar route not allowed: ${key}`);
  const allowedQuery = {
    '/lanes': new Set(['session_id']),
    '/models': new Set(['session_id', 'local']),
    '/sessions': new Set(['limit']),
    '/session': new Set(['id']),
  }[route.pathname] || new Set();
  for (const name of route.searchParams.keys()) {
    if (!allowedQuery.has(name)) throw new Error(`query parameter not allowed: ${name}`);
  }
  return route.pathname + route.search;
}

function sidecarRequest(method, rawRoute, payload) {
  return new Promise((resolve, reject) => {
    let boot;
    let route;
    try {
      boot = requireHandshake();
      route = normalizeRoute(method, rawRoute);
    } catch (err) {
      reject(err);
      return;
    }
    const body = payload === undefined || payload === null ? null : JSON.stringify(payload);
    const headers = {
      'X-Skynet-Token': boot.token,
      Accept: 'application/json',
    };
    if (body !== null) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request({
      hostname: '127.0.0.1',
      port: boot.port,
      path: route,
      method: String(method || 'GET').toUpperCase(),
      headers,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_SIDECAR_RESPONSE_BYTES) {
          req.destroy(new Error('sidecar response exceeded limit'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let data = {};
        if (raw) {
          try { data = JSON.parse(raw); } catch (_) { data = { error: raw.slice(0, 1000) }; }
        }
        resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode || 0, data });
      });
    });
    req.on('error', reject);
    req.setTimeout(35000, () => req.destroy(new Error('sidecar request timed out')));
    if (body !== null) req.write(body);
    req.end();
  });
}

function backendRequest(method, rawRoute, payload) {
  let route;
  try { route = normalizeRoute(method, rawRoute); }
  catch (err) { return Promise.reject(err); }
  if (backendKind === 'portable') {
    if (!portableRuntime) return Promise.reject(new Error('portable runtime unavailable'));
    return portableRuntime.api(String(method || 'GET').toUpperCase(), route, payload);
  }
  return sidecarRequest(method, route, payload);
}

function streamSidecarChat(sender, streamId, payload) {
  return new Promise((resolve, reject) => {
    let boot;
    try { boot = requireHandshake(); } catch (err) { reject(err); return; }
    const body = JSON.stringify(payload || {});
    const req = http.request({
      hostname: '127.0.0.1',
      port: boot.port,
      path: '/chat',
      method: 'POST',
      headers: {
        'X-Skynet-Token': boot.token,
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      if ((res.statusCode || 0) < 200 || (res.statusCode || 0) >= 300) {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          clearTimeout(wallClockTimer);
          const raw = Buffer.concat(chunks).toString('utf8');
          let detail = raw;
          try {
            const parsed = JSON.parse(raw);
            detail = parsed.error || parsed.detail || raw;
          } catch (_) { /* preserve raw */ }
          reject(new Error(`sidecar chat HTTP ${res.statusCode}: ${String(detail).slice(0, 500)}`));
        });
        return;
      }
      res.setEncoding('utf8');
      const decoder = createSseDecoder((frame) => {
        if (!sender.isDestroyed()) sender.send('skynet:chat-frame', { streamId, frame });
      }, MAX_SIDECAR_RESPONSE_BYTES);
      res.on('data', (chunk) => {
        try { decoder.push(chunk); } catch (err) { req.destroy(err); }
      });
      res.on('end', () => {
        decoder.end();
        clearTimeout(wallClockTimer);
        resolve({ ok: true, status: res.statusCode || 200 });
      });
    });
    const wallClockTimer = setTimeout(() => {
      const cleanup = stopSidecar();
      const suffix = cleanup.ok ? '' : `; sidecar containment failed for pid ${cleanup.pid}`;
      req.destroy(new Error(`sidecar chat exceeded ${TURN_TIMEOUT_SECONDS}s wall-clock limit${suffix}`));
    }, TURN_TIMEOUT_MS);
    req.on('error', (err) => {
      clearTimeout(wallClockTimer);
      reject(err);
    });
    req.write(body);
    req.end();
  });
}

async function streamBackendChat(sender, streamId, payload) {
  if (backendKind === 'portable') {
    if (!portableRuntime) return Promise.reject(new Error('portable runtime unavailable'));
    const terminalFrames = [];
    const result = await portableRuntime.chat(payload || {}, (frame) => {
      if (frame && ['delta', 'done', 'error'].includes(frame.event)) {
        terminalFrames.push(frame);
      } else if (!sender.isDestroyed()) {
        sender.send('skynet:chat-frame', { streamId, frame });
      }
    });
    return { ...result, terminalFrames };
  }
  return streamSidecarChat(sender, streamId, payload);
}

function createWindow() {
  win = new BrowserWindow({
    width: WIN_WIDTH,
    height: WIN_HEIGHT,
    minWidth: MIN_WIDTH,
    minHeight: MIN_HEIGHT,
    backgroundColor: BG,
    frame: false,
    show: false, // avoid the white flash before the dark UI paints
    title: 'Skynet',
    icon: path.join(__dirname, 'build', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: true,
      // The renderer displays model output. In a packaged build there is no reason to
      // ship a console that can read window.skynet.token out of memory.
      devTools: !app.isPackaged,
    },
  });

  // This window holds a credential to a filesystem-writing agent, so it gets none of
  // the ambient browser powers: no camera/mic/geolocation/notifications, no <webview>.
  win.webContents.on('will-attach-webview', (event) => event.preventDefault());

  win.once('ready-to-show', () => win.show());
  win.on('closed', () => { win = null; });

  // Security: this window renders untrusted model output. Never let it navigate away
  // from the local UI, and never let it spawn child windows — send links to the real
  // browser instead.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (event, url) => {
    if (url !== win.webContents.getURL()) {
      event.preventDefault();
      if (/^https:\/\//i.test(url)) shell.openExternal(url);
    }
  });

  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

function showFatal(message) {
  dialog.showErrorBox(
    'Skynet could not start',
    `${message}\n\nThe app refuses to open a chat window onto a backend it cannot reach — ` +
      `an empty cockpit reads as "idle" when the truth is "unreachable".`
  );
}

// One Skynet, one window. A second launch focuses the existing app (this is also what
// makes the taskbar behave like a real application rather than N stray processes).
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });

  // Windows uses the AppUserModelID to give the process its own taskbar identity/icon.
  app.setAppUserModelId('ai.skynet.desktop');

  app.whenReady().then(async () => {
    Menu.setApplicationMenu(null); // frameless app draws its own chrome
    // Deny every Chromium permission request by default (advisor P0): a markdown XSS in
    // the transcript must not be able to escalate into device or storage access.
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    try {
      handshake = await startBackend();
    } catch (err) {
      showFatal(String(err && err.message ? err.message : err));
      app.quit();
      return;
    }
    createWindow();
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
}

function trustedRenderer(event) {
  return isTrustedRenderer(win, event);
}

// The renderer receives presentation metadata only. The bearer token and sidecar
// address never cross the context-isolated preload boundary.
ipcMain.on('skynet:bootstrap', (event) => {
  if (!trustedRenderer(event)) {
    event.returnValue = null;
    return;
  }
  event.returnValue = handshake
    ? {
        backendReady: true,
        platform: process.platform,
        version: app.getVersion(),
        buildId: BUILD_STAMP.buildId,
        sourceDigest: BUILD_STAMP.sourceDigest,
        sourceCommit: BUILD_STAMP.sourceCommit,
        sourceMembersClean: BUILD_STAMP.sourceMembersClean,
        backendKind,
      }
    : null;
});

ipcMain.handle('skynet:api', async (event, rawRoute, options) => {
  if (!trustedRenderer(event)) return { ok: false, status: 403, data: { error: 'untrusted renderer' } };
  const opts = options && typeof options === 'object' ? options : {};
  const method = String(opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'POST') {
    return { ok: false, status: 405, data: { error: 'method not allowed' } };
  }
  try {
    return await backendRequest(method, rawRoute, opts.body === undefined ? null : opts.body);
  } catch (err) {
    return { ok: false, status: 503, data: { error: String(err && err.message ? err.message : err) } };
  }
});

ipcMain.handle('skynet:chat', async (event, streamId, payload) => {
  if (!trustedRenderer(event)) return { ok: false, status: 403, error: 'untrusted renderer' };
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(String(streamId || ''))) {
    return { ok: false, status: 400, error: 'invalid stream id' };
  }
  try {
    return await streamBackendChat(event.sender, String(streamId), payload);
  } catch (err) {
    return { ok: false, status: 503, error: String(err && err.message ? err.message : err) };
  }
});

ipcMain.handle('skynet:restart-sidecar', async (event) => {
  if (!trustedRenderer(event)) return { ok: false, status: 403, error: 'untrusted renderer' };
  try {
    return await restartBackend();
  } catch (err) {
    return { ok: false, status: 503, error: String(err && err.message ? err.message : err) };
  }
});

/**
 * Native folder picker for the working-folder control.
 *
 * The owner asked "what folder is it going to use?" -- the answer used to be a
 * hardcoded repo root. The renderer has no filesystem access and must not gain any, so
 * it can only REQUEST this dialog; the chosen path is handed to the sidecar, which is
 * what actually validates and stores it.
 */
ipcMain.handle('skynet:pick-folder', async (event) => {
  if (!trustedRenderer(event)) return { ok: false, canceled: true, error: 'untrusted renderer' };
  if (!win || win.isDestroyed()) return { ok: false, canceled: true };
  const result = await dialog.showOpenDialog(win, {
    title: 'Choose the folder Skynet works in',
    properties: ['openDirectory', 'createDirectory'],
  });
  if (result.canceled || !result.filePaths || !result.filePaths.length) {
    return { ok: true, canceled: true, path: '' };
  }
  return { ok: true, canceled: false, path: String(result.filePaths[0]) };
});

ipcMain.handle('skynet:window', (event, action) => {
  if (!trustedRenderer(event)) return { ok: false, status: 403 };
  if (!win || win.isDestroyed()) return { ok: false };
  if (action === 'minimize') win.minimize();
  else if (action === 'maximize') win.isMaximized() ? win.unmaximize() : win.maximize();
  else if (action === 'close') win.close();
  return { ok: true, maximized: win.isDestroyed() ? false : win.isMaximized() };
});

app.on('before-quit', (event) => {
  if (quitCleanupComplete) return;
  event.preventDefault();
  quitting = true;
  const result = stopBackend();
  if (!result.ok) {
    quitting = false;
    dialog.showErrorBox(
      'Skynet could not close safely',
      `The backend process tree for pid ${result.pid} is still alive. The app will remain open.`,
    );
    return;
  }
  quitCleanupComplete = true;
  app.quit();
});
process.on('exit', () => {
  const result = stopBackend();
  if (!result.ok) console.error('[sidecar] process-exit cleanup failed', result, lastSidecarExit);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
