/**
 * Skynet desktop preload bridge.
 *
 * The renderer is untrusted because it displays model output. It receives no bearer
 * token, address, Node primitive, raw IPC object, or arbitrary channel. All sidecar
 * traffic is owned by main.js and crosses this bridge through a tiny allowlisted API.
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const boot = ipcRenderer.sendSync('skynet:bootstrap') || {};
let sequence = 0;

function windowAction(action) {
  return ipcRenderer.invoke('skynet:window', action);
}

function api(path, options) {
  const opts = options && typeof options === 'object' ? options : {};
  return ipcRenderer.invoke('skynet:api', String(path || ''), {
    method: String(opts.method || 'GET'),
    body: opts.body === undefined ? null : opts.body,
  });
}

function chat(payload, onFrame) {
  if (typeof onFrame !== 'function') return Promise.reject(new Error('chat frame handler required'));
  sequence += 1;
  const streamId = `renderer_${Date.now()}_${sequence}`;
  const listener = (_event, envelope) => {
    if (!envelope || envelope.streamId !== streamId) return;
    onFrame(envelope.frame || {});
  };
  ipcRenderer.on('skynet:chat-frame', listener);
  return ipcRenderer.invoke('skynet:chat', streamId, payload || {}).then((result) => {
    // The in-process portable runtime can finish and resolve in the same event-loop
    // turn. Replaying its terminal frames here makes delivery atomic with the invoke
    // response, before finally removes the live phase listener.
    if (result && Array.isArray(result.terminalFrames)) {
      result.terminalFrames.forEach((frame) => onFrame(frame || {}));
    }
    return result;
  }).finally(() => {
    ipcRenderer.removeListener('skynet:chat-frame', listener);
  });
}

contextBridge.exposeInMainWorld('skynet', Object.freeze({
  backendReady: Boolean(boot.backendReady),
  platform: String(boot.platform || process.platform),
  version: String(boot.version || ''),
  // Build identity travels to the UI so a screenshot is enough to say WHICH bytes are running.
  // Empty buildId means an unstamped dev run, which the renderer must render as such.
  buildId: String(boot.buildId || ''),
  sourceDigest: String(boot.sourceDigest || ''),
  sourceCommit: String(boot.sourceCommit || ''),
  sourceMembersClean: boot.sourceMembersClean === true,
  backendKind: String(boot.backendKind || 'unknown'),
  api,
  chat,
  restartSidecar: () => ipcRenderer.invoke('skynet:restart-sidecar'),
  // Opens the OS folder dialog in the MAIN process and returns only the chosen path.
  // The renderer gets no filesystem handle, no directory listing, and no default path.
  pickFolder: () => ipcRenderer.invoke('skynet:pick-folder'),
  minimize: () => windowAction('minimize'),
  maximize: () => windowAction('maximize'),
  close: () => windowAction('close'),
  onSidecarDown: (handler) => {
    if (typeof handler !== 'function') return function () {};
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on('skynet:sidecar-down', listener);
    return () => ipcRenderer.removeListener('skynet:sidecar-down', listener);
  },
}));
