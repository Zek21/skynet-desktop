/* ==========================================================================
   Skynet desktop renderer - app.js

   contextIsolation is ON: there is NO require(), NO node API here.
   The renderer never receives the sidecar port or bearer token. The narrow preload
   bridge asks the main process to perform allowlisted JSON requests and streams
   parsed SSE frames back over one transaction-owned IPC subscription.
   ========================================================================== */
'use strict';

(function () {

  /* ---------------------------------------------------------------- bridge */

  var FALLBACK = {
    backendReady: false,
    platform: 'unknown',
    api: null,
    chat: null,
    minimize: function () {},
    maximize: function () {},
    close: function () {}
  };

  var bridge = (typeof window !== 'undefined' && window.skynet) ? window.skynet : FALLBACK;
  var HAS_BRIDGE = !!(typeof window !== 'undefined' && window.skynet);

  /* ------------------------------------------------------------------- dom */

  function $(id) { return document.getElementById(id); }

  var el = {
    navToggle: $('navToggle'),
    tbBuild: $('tbBuild'),
    tbAppBuild: $('tbAppBuild'),
    supportCard: $('supportCard'),
    supportClose: $('supportClose'),
    supportLink: $('supportLink'),
    winMin: $('winMin'),
    winMax: $('winMax'),
    winClose: $('winClose'),
    sidebar: $('sidebar'),
    scrim: $('scrim'),
    newChat: $('newChat'),
    sessionList: $('sessionList'),
    laneFoot: $('laneFoot'),
    laneDot: $('laneDot'),
    laneName: $('laneName'),
    laneModel: $('laneModel'),
    banner: $('banner'),
    bannerText: $('bannerText'),
    bannerTag: $('bannerTag'),
    bannerRetry: $('bannerRetry'),
    transcript: $('transcript'),
    empty: $('empty'),
    turns: $('turns'),
    input: $('input'),
    laneChip: $('laneChip'),
    chipGlyph: $('chipGlyph'),
    chipLabel: $('chipLabel'),
    stopBtn: $('stopBtn'),
    sendBtn: $('sendBtn'),
    main: $('main'),
    settingsBtn: $('settingsBtn'),
    settings: $('settings'),
    settingsScrim: $('settingsScrim'),
    settingsClose: $('settingsClose'),
    subsList: $('subsList'),
    subsSummary: $('subsSummary'),
    lanePop: $('lanePop'),
    lanePopList: $('lanePopList'),
    lanePopSub: $('lanePopSub'),
    orchestrationToggle: $('orchestrationToggle'),
    orchestrationState: $('orchestrationState'),
    orchestrationNote: $('orchestrationNote'),
    roleBoard: $('roleBoard'),
    orchestratorRows: $('orchestratorRows'),
    workerRows: $('workerRows'),
    workerAdd: $('workerAdd'),
    workerContention: $('workerContention'),
    advisorRows: $('advisorRows'),
    advisorAdd: $('advisorAdd'),
    workspacePath: $('workspacePath'),
    workspaceState: $('workspaceState'),
    workspaceFacts: $('workspaceFacts'),
    workspaceWarn: $('workspaceWarn'),
    workspacePick: $('workspacePick'),
    workspaceReset: $('workspaceReset'),
    localServers: $('localServers'),
    apiList: $('apiList'),
    apiKeysState: $('apiKeysState'),
    apiAdd: $('apiAdd'),
    apiForm: $('apiForm'),
    apiProvider: $('apiProvider'),
    apiLabel: $('apiLabel'),
    apiBaseWrap: $('apiBaseWrap'),
    apiBaseUrl: $('apiBaseUrl'),
    apiKey: $('apiKey'),
    apiLocalWrap: $('apiLocalWrap'),
    apiAllowLocal: $('apiAllowLocal'),
    apiVerdict: $('apiVerdict'),
    apiModelWrap: $('apiModelWrap'),
    apiModel: $('apiModel'),
    apiTest: $('apiTest'),
    apiSave: $('apiSave'),
    apiCancel: $('apiCancel'),
    toast: $('toast')
  };

  /* ----------------------------------------------------------------- state */

  var state = {
    sessionId: null,
    sessions: [],
    lanes: [],
    activeLane: null,
    activeModel: null,
    pendingProvider: 'council',
    pendingModel: null,
    activeMode: 'best',
    advancedOpen: false,
    // Roles are ROWS ({lane, model}), not a set of lane ids. The owner could not put
    // the same model in two rows because the old shape made a model a single token.
    orchestration: {
      enabled: false,
      orchestrator: null,
      workers: [],
      advisors: []
    },
    disabledModels: {},
    laneModels: {},        /* owner's per-lane model pick, applied to chat + roles */
    workspace: null,
    apiKeys: [],
    providers: [],
    localServers: [],
    encryption: '',
    apiFormOpen: false,
    apiEditingId: '',
    apiTested: null,
    streaming: false,
    live: null
  };

  var MODES = [
    { id: 'fast', label: 'Fast', provider: 'codex', detail: 'One reliable model' },
    { id: 'best', label: 'Best', provider: 'council', detail: 'Cross-checked and synthesized' },
    { id: 'code', label: 'Code', provider: 'codex', detail: 'Workspace-aware coding agent' },
    { id: 'research', label: 'Research', provider: 'council', detail: 'Evidence-focused multi-model run' }
  ];

  var STATUS_GLYPH = {
    ready: '\u25CF',        /* filled circle */
    unavailable: '\u25CB',  /* hollow circle */
    gated: '\u2298',        /* circled slash */
    retired: '\u29B8'       /* circled reverse slash */
  };

  function glyphFor(status) {
    var s = String(status || '').toLowerCase();
    return STATUS_GLYPH[s] || STATUS_GLYPH.unavailable;
  }

  function statusKey(status) {
    var s = String(status || '').toLowerCase();
    if (s === 'ready' || s === 'unavailable' || s === 'gated' || s === 'retired') return s;
    return 'unknown';
  }

  /* ----------------------------------------------------------------- utils */

  /* Model output is UNTRUSTED. It is rendered only with DOM nodes + textContent. */
  function escapeHtml(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /* External links are HTTPS-only. Anything else remains inert text. */
  function safeUrl(u) {
    var t = String(u || '').trim().replace(/[\u0000-\u001F\u007F]/g, '');
    return /^https:\/\//i.test(t) ? t : '';
  }

  function parseTs(ts) {
    if (ts === null || ts === undefined || ts === '') return null;
    if (typeof ts === 'number' && isFinite(ts)) {
      return ts > 1e11 ? ts : ts * 1000;   /* seconds vs milliseconds */
    }
    var n = Number(ts);
    if (!isNaN(n) && String(ts).trim() !== '' && /^[0-9.]+$/.test(String(ts).trim())) {
      return n > 1e11 ? n : n * 1000;
    }
    var p = Date.parse(String(ts));
    return isNaN(p) ? null : p;
  }

  function relTime(ts) {
    var ms = parseTs(ts);
    if (ms === null) return '';
    var diff = Date.now() - ms;
    if (diff < 0) diff = 0;
    var sec = Math.floor(diff / 1000);
    if (sec < 45) return 'just now';
    var min = Math.floor(sec / 60);
    if (min < 60) return min + (min === 1 ? ' min ago' : ' mins ago');
    var hr = Math.floor(min / 60);
    if (hr < 24) return hr + (hr === 1 ? ' hour ago' : ' hours ago');
    var day = Math.floor(hr / 24);
    if (day < 7) return day + (day === 1 ? ' day ago' : ' days ago');
    var d = new Date(ms);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function clockTime(ts) {
    var ms = parseTs(ts);
    if (ms === null) return '';
    return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  function fmtSeconds(ms) {
    var n = Number(ms);
    if (!isFinite(n) || n < 0) return '';
    return (n / 1000).toFixed(1) + 's';
  }

  var toastTimer = null;
  function toast(msg) {
    if (!el.toast) return;
    el.toast.textContent = String(msg);
    el.toast.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.toast.hidden = true; }, 2600);
  }

  /* `tag` names WHAT is wrong. Retry only appears when restarting the backend is the
     actual remedy - offering it for "no model is signed in" would be a dead button. */
  function showBanner(text, tag) {
    if (!el.banner) return;
    el.bannerText.textContent = String(text);
    if (el.bannerTag) el.bannerTag.textContent = String(tag || 'OFFLINE');
    if (el.bannerRetry) el.bannerRetry.hidden = !!tag;
    el.banner.hidden = false;
  }

  function hideBanner() {
    if (el.banner) el.banner.hidden = true;
  }

  function errText(e) {
    if (!e) return 'unknown error';
    if (e.message) return String(e.message);
    return String(e);
  }

  /* ------------------------------------------------------------------- api */

  async function api(path, opts) {
    if (!bridge || typeof bridge.api !== 'function') throw new Error('sidecar bridge unavailable');
    var o = opts || {};
    var body = o.body;
    if (typeof body === 'string' && body) {
      try { body = JSON.parse(body); } catch (e0) { throw new Error('invalid local JSON payload'); }
    }
    var res = await bridge.api(path, { method: o.method || 'GET', body: body });
    var data = res && res.data ? res.data : {};
    if (!res || !res.ok) {
      var status = res && res.status ? res.status : 503;
      var detail = (data && (data.detail || data.error)) || ('HTTP ' + status);
      var err = new Error(String(detail).slice(0, 400));
      err.status = status;
      err.data = data;
      throw err;
    }
    return data;
  }

  /* ==========================================================================
     MARKDOWN - small, self-contained, offline. No CDN, no dependency.
     Order matters: fenced code is lifted out FIRST, everything else is HTML
     escaped BEFORE any tag is produced, so model output can never inject DOM.
     ========================================================================== */

  function codeBlockHtml(lang, code) {
    var label = String(lang || '').trim() || 'code';
    return '<div class="code-block">' +
             '<div class="code-head">' +
               '<span class="code-lang">' + escapeHtml(label) + '</span>' +
               '<button class="copy-btn" type="button">Copy</button>' +
             '</div>' +
             '<pre class="code-body"><code>' + escapeHtml(code) + '</code></pre>' +
           '</div>';
  }

  /* input here is ALREADY html-escaped */
  function inlineMd(s) {
    var codes = [];
    s = s.replace(/`([^`]+)`/g, function (m, c) {
      codes.push(c);
      return '\u0001' + (codes.length - 1) + '\u0001';
    });
    s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)[^)]*\)/g, function (m, alt, url) {
      return '<a href="' + safeUrl(url) + '" target="_blank" rel="noreferrer noopener">' +
             (alt || 'image') + '</a>';
    });
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)[^)]*\)/g, function (m, txt, url) {
      return '<a href="' + safeUrl(url) + '" target="_blank" rel="noreferrer noopener">' +
             txt + '</a>';
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[\s(\[])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    s = s.replace(/~~([^~]+)~~/g, '<del>$1</del>');
    s = s.replace(/\u0001(\d+)\u0001/g, function (m, idx) {
      var c = codes[Number(idx)];
      return '<code class="md-inline">' + (c === undefined ? '' : c) + '</code>';
    });
    return s;
  }

  function listItemOf(line) {
    var ul = /^(\s*)[-*+]\s+(.*)$/.exec(line);
    if (ul) return { indent: ul[1].replace(/\t/g, '  ').length, ordered: false, text: ul[2] };
    var ol = /^(\s*)\d{1,9}[.)]\s+(.*)$/.exec(line);
    if (ol) return { indent: ol[1].replace(/\t/g, '  ').length, ordered: true, text: ol[2] };
    return null;
  }

  function renderList(items, pos, depth) {
    var ordered = items[pos].ordered;
    var indent = items[pos].indent;
    var html = ordered ? '<ol>' : '<ul>';
    while (pos < items.length && items[pos].indent >= indent) {
      if (items[pos].indent > indent) {
        var stray = renderList(items, pos, depth + 1);
        html += stray.html;
        pos = stray.pos;
        continue;
      }
      if (items[pos].ordered !== ordered) break;
      var body = inlineMd(escapeHtml(items[pos].text));
      pos += 1;
      var nested = '';
      if (depth < 4 && pos < items.length && items[pos].indent > indent) {
        var sub = renderList(items, pos, depth + 1);
        nested = sub.html;
        pos = sub.pos;
      }
      html += '<li>' + body + nested + '</li>';
    }
    html += ordered ? '</ol>' : '</ul>';
    return { html: html, pos: pos };
  }

  function renderMarkdown(src, depth) {
    depth = depth || 0;
    var text = String(src === null || src === undefined ? '' : src)
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
    var lines = text.split('\n');
    var out = [];
    var i = 0;

    while (i < lines.length) {
      var line = lines[i];

      if (/^\s*$/.test(line)) { i += 1; continue; }

      var fence = /^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+.#\-]*)\s*$/.exec(line);
      if (fence) {
        var marker = fence[1].charAt(0);
        var lang = fence[2] || '';
        var closer = new RegExp('^\s*' + marker + '{3,}\s*$');
        var buf = [];
        i += 1;
        while (i < lines.length && !closer.test(lines[i])) { buf.push(lines[i]); i += 1; }
        if (i < lines.length) i += 1;
        out.push(codeBlockHtml(lang, buf.join('\n')));
        continue;
      }

      var head = /^(#{1,6})\s+(.*)$/.exec(line);
      if (head) {
        var lvl = head[1].length;
        out.push('<h' + lvl + '>' + inlineMd(escapeHtml(head[2].trim())) + '</h' + lvl + '>');
        i += 1;
        continue;
      }

      if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) { out.push('<hr />'); i += 1; continue; }

      if (/^\s*>/.test(line)) {
        var quoted = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) {
          quoted.push(lines[i].replace(/^\s*>\s?/, ''));
          i += 1;
        }
        var innerHtmlText = depth < 3
          ? renderMarkdown(quoted.join('\n'), depth + 1)
          : '<p>' + inlineMd(escapeHtml(quoted.join(' '))) + '</p>';
        out.push('<blockquote>' + innerHtmlText + '</blockquote>');
        continue;
      }

      if (listItemOf(line)) {
        var items = [];
        while (i < lines.length) {
          var item = listItemOf(lines[i]);
          if (!item) break;
          items.push(item);
          i += 1;
        }
        out.push(renderList(items, 0, 0).html);
        continue;
      }

      var para = [];
      while (i < lines.length &&
             !/^\s*$/.test(lines[i]) &&
             !/^\s*(`{3,}|~{3,})/.test(lines[i]) &&
             !/^#{1,6}\s+/.test(lines[i]) &&
             !/^\s*>/.test(lines[i]) &&
             !/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(lines[i]) &&
             !listItemOf(lines[i])) {
        para.push(lines[i]);
        i += 1;
      }
      if (para.length) {
        out.push('<p>' + inlineMd(escapeHtml(para.join('\n'))).replace(/\n/g, '<br />') + '</p>');
      }
    }

    return out.join('\n');
  }

  function appendInlineDom(parent, source, depth) {
    var text = String(source || '');
    if (depth > 5 || !text) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    // Underscores remain literal so identifiers such as SKYNET_DESKTOP_PROOF are
    // never silently changed. Emphasis uses asterisks; code spans remain explicit.
    var token = /(`[^`\n]+`|\[[^\]\n]+\]\([^\s)]+\)|\*\*[^*\n]+\*\*|~~[^~\n]+~~|\*[^*\n]+\*)/g;
    var cursor = 0;
    var match;
    while ((match = token.exec(text)) !== null) {
      if (match.index > cursor) parent.appendChild(document.createTextNode(text.slice(cursor, match.index)));
      var raw = match[0];
      var node;
      var inner;
      var link = /^\[([^\]\n]+)\]\(([^\s)]+)\)$/.exec(raw);
      if (raw.charAt(0) === '`') {
        node = makeEl('code', 'md-inline');
        node.textContent = raw.slice(1, -1);
      } else if (link) {
        var href = safeUrl(link[2]);
        if (href) {
          node = makeEl('a');
          node.href = href;
          node.target = '_blank';
          node.rel = 'noreferrer noopener';
          node.textContent = link[1];
        } else {
          node = document.createTextNode(link[1]);
        }
      } else {
        var tag = 'em';
        if (raw.slice(0, 2) === '**') tag = 'strong';
        else if (raw.slice(0, 2) === '~~') tag = 'del';
        var trim = (tag === 'em') ? 1 : 2;
        inner = raw.slice(trim, -trim);
        node = makeEl(tag);
        appendInlineDom(node, inner, depth + 1);
      }
      parent.appendChild(node);
      cursor = token.lastIndex;
    }
    if (cursor < text.length) parent.appendChild(document.createTextNode(text.slice(cursor)));
  }

  function codeBlockDom(lang, code) {
    var wrap = makeEl('div', 'code-block');
    var head = makeEl('div', 'code-head');
    head.appendChild(makeEl('span', 'code-lang', String(lang || '').trim() || 'code'));
    var copy = makeEl('button', 'copy-btn', 'Copy');
    copy.type = 'button';
    head.appendChild(copy);
    var pre = makeEl('pre', 'code-body');
    var codeNode = makeEl('code');
    codeNode.textContent = String(code || '');
    pre.appendChild(codeNode);
    wrap.appendChild(head);
    wrap.appendChild(pre);
    return wrap;
  }

  function buildMarkdownDom(source, depth) {
    var fragment = document.createDocumentFragment();
    var lines = String(source === null || source === undefined ? '' : source)
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '')
      .split('\n');
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      if (/^\s*$/.test(line)) { i += 1; continue; }

      var fence = /^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+.#\-]*)\s*$/.exec(line);
      if (fence) {
        var marker = fence[1].charAt(0);
        var close = new RegExp('^\\s*' + marker + '{3,}\\s*$');
        var codeLines = [];
        i += 1;
        while (i < lines.length && !close.test(lines[i])) { codeLines.push(lines[i]); i += 1; }
        if (i < lines.length) i += 1;
        fragment.appendChild(codeBlockDom(fence[2], codeLines.join('\n')));
        continue;
      }

      var heading = /^(#{1,6})\s+(.*)$/.exec(line);
      if (heading) {
        var headingNode = makeEl('h' + heading[1].length);
        appendInlineDom(headingNode, heading[2].trim(), 0);
        fragment.appendChild(headingNode);
        i += 1;
        continue;
      }
      if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
        fragment.appendChild(makeEl('hr'));
        i += 1;
        continue;
      }
      if (/^\s*>/.test(line)) {
        var quoteLines = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) {
          quoteLines.push(lines[i].replace(/^\s*>\s?/, ''));
          i += 1;
        }
        var quote = makeEl('blockquote');
        quote.appendChild(depth < 3 ? buildMarkdownDom(quoteLines.join('\n'), depth + 1) :
          document.createTextNode(quoteLines.join(' ')));
        fragment.appendChild(quote);
        continue;
      }

      var firstItem = listItemOf(line);
      if (firstItem) {
        var list = makeEl(firstItem.ordered ? 'ol' : 'ul');
        while (i < lines.length) {
          var item = listItemOf(lines[i]);
          if (!item || item.ordered !== firstItem.ordered) break;
          var li = makeEl('li');
          appendInlineDom(li, item.text, 0);
          list.appendChild(li);
          i += 1;
        }
        fragment.appendChild(list);
        continue;
      }

      var paraLines = [];
      while (i < lines.length && !/^\s*$/.test(lines[i]) &&
             !/^\s*(`{3,}|~{3,})/.test(lines[i]) && !/^#{1,6}\s+/.test(lines[i]) &&
             !/^\s*>/.test(lines[i]) && !listItemOf(lines[i]) &&
             !/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(lines[i])) {
        paraLines.push(lines[i]);
        i += 1;
      }
      var paragraph = makeEl('p');
      for (var p = 0; p < paraLines.length; p += 1) {
        if (p) paragraph.appendChild(makeEl('br'));
        appendInlineDom(paragraph, paraLines[p], 0);
      }
      fragment.appendChild(paragraph);
    }
    return fragment;
  }

  function mountMarkdown(node, src) {
    node.replaceChildren(buildMarkdownDom(src, 0));
  }

  /* ==========================================================================
     TRANSCRIPT
     ========================================================================== */

  function nearBottom() {
    if (!el.transcript) return true;
    var slack = el.transcript.scrollHeight - el.transcript.scrollTop - el.transcript.clientHeight;
    return slack < 120;
  }

  function scrollToBottom(force) {
    if (!el.transcript) return;
    if (force || nearBottom()) {
      el.transcript.scrollTop = el.transcript.scrollHeight;
    }
  }

  function setEmptyVisible(visible) {
    if (el.empty) el.empty.hidden = !visible;
    // Design review, round 1: while the session is empty the composer must sit directly
    // under the subtitle, not docked at the bottom of a tall void, so the action reads as
    // the subject of the screen. It docks to the bottom once a conversation exists.
    if (el.main) el.main.classList.toggle('is-empty', !!visible);
  }

  function clearTranscript() {
    if (el.turns) el.turns.replaceChildren();
    setEmptyVisible(true);
  }

  function makeEl(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function addUserTurn(text, ts) {
    setEmptyVisible(false);
    var stick = nearBottom();

    var turn = makeEl('article', 'turn turn-user');
    var head = makeEl('div', 'turn-head');
    head.appendChild(makeEl('span', 'turn-avatar'));
    head.appendChild(makeEl('span', null, 'You'));
    var t = clockTime(ts || Date.now());
    if (t) head.appendChild(makeEl('span', 'turn-time', t));
    turn.appendChild(head);

    var bubble = makeEl('div', 'bubble');
    bubble.textContent = String(text);   /* raw text, never innerHTML */
    turn.appendChild(bubble);

    el.turns.appendChild(turn);
    scrollToBottom(stick);
    return turn;
  }

  function addAssistantTurn(options) {
    var opts = options || {};
    setEmptyVisible(false);
    var stick = nearBottom();

    var turn = makeEl('article', 'turn turn-assistant');

    var head = makeEl('div', 'turn-head');
    head.appendChild(makeEl('span', 'turn-avatar'));
    head.appendChild(makeEl('span', null, 'Skynet'));
    var timeEl = makeEl('span', 'turn-time', opts.ts ? clockTime(opts.ts) : '');
    head.appendChild(timeEl);
    turn.appendChild(head);

    var handle = {
      root: turn,
      timeEl: timeEl,
      thinking: null,
      thinkBody: null,
      thinkSummary: null,
      md: null,
      phases: [],
      startedAt: Date.now(),
      ticker: null
    };

    if (opts.withThinking) {
      var panel = makeEl('div', 'thinking is-live is-collapsed');

      var thead = makeEl('button', 'think-head');
      thead.type = 'button';
      thead.appendChild(makeEl('span', 'think-pulse'));
      thead.appendChild(makeEl('span', 'think-title', 'Activity'));
      var summary = makeEl('span', 'think-summary', 'starting run\u2026');
      thead.appendChild(summary);
      thead.appendChild(makeEl('span', 'think-caret'));
      thead.addEventListener('click', function () {
        panel.classList.toggle('is-collapsed');
      });

      var tbody = makeEl('div', 'think-body');

      panel.appendChild(thead);
      panel.appendChild(tbody);
      turn.appendChild(panel);

      handle.thinking = panel;
      handle.thinkBody = tbody;
      handle.thinkSummary = summary;

      handle.ticker = setInterval(function () {
        if (!panel.classList.contains('is-live')) return;
        var last = handle.phases.length ? handle.phases[handle.phases.length - 1] : null;
        var tail = last ? (last.phase || 'working') : 'working';
        summary.textContent = fmtSeconds(Date.now() - handle.startedAt) + ' \u00B7 ' + tail;
      }, 200);
    }

    var bubble = makeEl('div', 'bubble');
    var md = makeEl('div', 'md');
    bubble.appendChild(md);
    turn.appendChild(bubble);
    handle.md = md;

    if (opts.withThinking) {
      var typing = makeEl('div', 'typing');
      typing.appendChild(makeEl('i'));
      typing.appendChild(makeEl('i'));
      typing.appendChild(makeEl('i'));
      md.appendChild(typing);
    }

    el.turns.appendChild(turn);
    scrollToBottom(stick);
    return handle;
  }

  function addPhase(handle, payload) {
    if (!handle || !handle.thinkBody) return;
    var phase = String((payload && payload.phase) || 'phase');
    var lane = payload && payload.lane ? String(payload.lane) : '';
    var text = payload && payload.text !== undefined && payload.text !== null
      ? String(payload.text) : '';

    handle.phases.push({ phase: phase, lane: lane, text: text });

    var stickPanel = (handle.thinkBody.scrollHeight - handle.thinkBody.scrollTop -
                      handle.thinkBody.clientHeight) < 60;
    var stick = nearBottom();

    var row = makeEl('div', 'phase');
    row.setAttribute('data-phase', phase.toLowerCase());
    row.appendChild(makeEl('span', 'phase-tag', '[' + phase + ']'));
    if (lane) row.appendChild(makeEl('span', 'phase-lane', lane));
    if (text) row.appendChild(makeEl('span', 'phase-text', text));

    handle.thinkBody.appendChild(row);
    if (stickPanel) handle.thinkBody.scrollTop = handle.thinkBody.scrollHeight;
    scrollToBottom(stick);
  }

  function stopTicker(handle) {
    if (handle && handle.ticker) {
      clearInterval(handle.ticker);
      handle.ticker = null;
    }
  }

  function finishThinking(handle, summaryText, kind) {
    if (!handle) return;
    stopTicker(handle);
    if (!handle.thinking) return;
    handle.thinking.classList.remove('is-live');
    handle.thinking.classList.add('is-collapsed');
    if (kind === 'error') handle.thinking.classList.add('is-error');
    if (handle.thinkSummary) handle.thinkSummary.textContent = summaryText;
    if (!handle.phases.length && handle.thinkBody) {
      handle.thinkBody.appendChild(makeEl('div', 'phase',
        'no phase frames were sent for this turn'));
    }
  }

  /* ==========================================================================
     LANES
     ========================================================================== */

  function laneById(id) {
    if (!id) return null;
    for (var i = 0; i < state.lanes.length; i += 1) {
      if (String(state.lanes[i].id) === String(id)) return state.lanes[i];
    }
    return null;
  }

  function modeById(id) {
    for (var i = 0; i < MODES.length; i += 1) {
      if (MODES[i].id === id) return MODES[i];
    }
    if (id === 'advanced') return { id: 'advanced', label: 'Advanced', detail: 'Direct internal route' };
    return MODES[1];
  }

  function paintLane() {
    // With Fleet roles on, the ORCHESTRATOR answers - whatever route is picked here.
    // Found on the packaged build 2026-08-05: the footer read "Ollama" while the turn
    // actually ran on codex, which is the footer lying about where the answer came from.
    var orchestrating = state.orchestration.enabled && state.orchestration.orchestrator;
    var effectiveLane = orchestrating
      ? state.orchestration.orchestrator.lane
      : (state.pendingProvider || state.activeLane);
    var lane = laneById(effectiveLane);
    var label = lane ? (lane.label || lane.id) : (effectiveLane || 'no lane');
    var status = lane ? statusKey(lane.status) : 'unknown';
    var model = orchestrating
      ? (state.orchestration.orchestrator.model || (lane ? laneModel(lane) : ''))
      : (state.pendingModel || (lane ? laneModel(lane) : '') || state.activeModel || '');
    var mode = modeById(state.activeMode);

    // Design review, round 1: the footer said "Local council / subscription default",
    // which is internal vocabulary leaking into the product surface and tells a user
    // nothing. Healthy state is now a single word, and detail appears ONLY when the user
    // has to act on it. The route name and model stay in the tooltip for diagnostics.
    // Round 2 (owner, 2026-08-05): "i cant even see what models are open or what". A
    // healthy state that says only "Ready" hides the one fact the owner asked for, so
    // the running model is now always on screen, not only in a tooltip.
    var needsAction = status !== 'ready';
    if (el.laneName) el.laneName.textContent = needsAction ? label : (label || 'Ready');
    if (el.laneModel) {
      var detail = needsAction
        ? (status === 'gated' ? 'needs sign-in' : status)
        : (model || 'default model');
      el.laneModel.textContent = detail;
      el.laneModel.hidden = !detail;
    }
    if (el.laneDot) el.laneDot.setAttribute('data-status', status);
    if (el.laneFoot) {
      el.laneFoot.title = label + (model ? ' \u00b7 ' + model : '') + ' \u00b7 ' + status;
    }

    // "Mode: Best" reads as a changeable routing decision; a bare "Best" reads as a label.
    if (el.chipLabel) {
      el.chipLabel.textContent = state.orchestration.enabled
        ? 'Mode: Orchestrated' : 'Mode: ' + mode.label;
    }
    if (el.chipGlyph) {
      el.chipGlyph.textContent = glyphFor(status);
      el.chipGlyph.setAttribute('data-status', status);
    }
    if (el.laneChip) {
      el.laneChip.title = mode.label + ': ' + mode.detail + ' \u00B7 route ' + label +
                          (model ? ' \u00B7 ' + model : '') + ' \u00B7 ' + status;
    }
  }

  function orchestrationCandidates() {
    return state.lanes.filter(function (lane) {
      var id = String(lane.id || '');
      if (statusKey(lane.status) !== 'ready' || !modelEnabled(id)) return false;
      // The backend states which lanes can execute (BYOK API lanes can; the merged
      // council and the browser review lanes cannot). Trust it when it answers.
      if (typeof lane.can_orchestrate === 'boolean') return lane.can_orchestrate;
      return id !== 'council' && id !== 'gemini' && id.indexOf('cdp-') !== 0;
    });
  }

  // Advisors REVIEW, they never execute, so the browser subscription lanes qualify here
  // even though they are excluded from orchestrator and worker duty above. Before this
  // role existed those lanes could not be assigned at all.
  function advisorCandidates() {
    return state.lanes.filter(function (lane) {
      var id = String(lane.id || '');
      return statusKey(lane.status) === 'ready' && modelEnabled(id) && id !== 'council';
    });
  }

  /* ============================================================ models panel

     Owner review of the shipped panel, 2026-08-05: "i cant even see what models are
     open or what and cant use the same model for one row". Both are answered here:
     every lane now shows the account it is signed in as, the models that account can
     really run, and a plain reason when it cannot run at all; and roles are ROWS, so a
     model may be used as many times as the owner wants.
     ============================================================================ */

  function loadDisabledModels() {
    try {
      var raw = window.localStorage.getItem('skynet.disabledModels.v1');
      var parsed = raw ? JSON.parse(raw) : null;
      if (parsed && typeof parsed === 'object') state.disabledModels = parsed;
    } catch (e) { /* a corrupt preference must never hide the whole fleet */ }
    try {
      var rawModels = window.localStorage.getItem('skynet.laneModels.v1');
      var models = rawModels ? JSON.parse(rawModels) : null;
      if (models && typeof models === 'object') state.laneModels = models;
    } catch (e2) { /* same: a bad pick falls back to the lane default */ }
  }

  function saveDisabledModels() {
    try {
      window.localStorage.setItem('skynet.disabledModels.v1', JSON.stringify(state.disabledModels));
      window.localStorage.setItem('skynet.laneModels.v1', JSON.stringify(state.laneModels));
    } catch (e) { /* local preference persistence is optional */ }
  }

  function modelEnabled(id) {
    return !state.disabledModels[String(id)];
  }

  function setModelEnabled(id, enabled) {
    if (enabled) delete state.disabledModels[String(id)];
    else state.disabledModels[String(id)] = true;
    saveDisabledModels();
    sanitizeOrchestration();
    renderModels();
    renderOrchestration();
    renderLanePop();
    paintLane();
  }

  /* The model a lane will actually run: the owner's pick when it is still offered by
     that lane, otherwise the lane's own default. Never a remembered model the account
     has since lost access to. */
  function laneModel(lane) {
    var id = String(lane.id || '');
    var picked = String(state.laneModels[id] || '');
    var offered = Array.isArray(lane.models) ? lane.models.map(String) : [];
    if (picked && (!offered.length || offered.indexOf(picked) >= 0)) return picked;
    return String(lane.model || (offered.length ? offered[0] : ''));
  }

  function setLaneModel(id, model) {
    if (model) state.laneModels[String(id)] = String(model);
    else delete state.laneModels[String(id)];
    saveDisabledModels();
    var lane = laneById(id);
    if (lane && String(state.activeLane) === String(id)) {
      pickProvider(String(id), laneModel(lane), lane.label || id);
    }
    renderModels();
    renderOrchestration();
    paintLane();
  }

  function kindLabel(kind) {
    var map = {
      cli: 'CLI', browser: 'Browser', api: 'API key', merged: 'Merged',
      extension: 'Extension', local: 'Local server'
    };
    return map[String(kind || '')] || '';
  }

  function selectEl(options, value, onChange, ariaLabel) {
    var select = makeEl('select', 'row-select');
    if (ariaLabel) select.setAttribute('aria-label', ariaLabel);
    options.forEach(function (option) {
      var node = makeEl('option', null, option.label);
      node.value = option.value;
      if (String(option.value) === String(value)) node.selected = true;
      select.appendChild(node);
    });
    select.addEventListener('change', function () { onChange(select.value); });
    return select;
  }

  /**
   * The control that ends "the CLI is not installed on this PC".
   *
   * Two honest outcomes only. If the vendor publishes a platform build we can fetch and
   * hash-verify, this offers to install it. If they do not — agy ships inside the
   * Antigravity IDE — it says so and opens the real download page, rather than pretending
   * to an install it cannot perform.
   */
  function installControl(lane, id) {
    if (lane.manual_install_url) {
      var open = makeEl('button', 'ghost-btn', 'Get it');
      open.type = 'button';
      open.title = String(lane.reason || '');
      open.addEventListener('click', function (ev) {
        ev.stopPropagation();
        window.open(String(lane.manual_install_url), '_blank');
      });
      return open;
    }
    var button = makeEl('button', 'ghost-btn', lane.installing ? 'Installing…' : 'Install');
    button.type = 'button';
    button.disabled = Boolean(lane.installing);
    button.addEventListener('click', async function (ev) {
      ev.stopPropagation();
      button.disabled = true;
      button.textContent = 'Installing…';
      // Hundreds of MB from the vendor's own registry: say what is happening rather than
      // leaving a dead button for a minute.
      toast('Downloading the ' + (lane.label || id) + ' CLI — this is a few hundred MB.');
      try {
        var res = await api('/cli/install', { method: 'POST', body: JSON.stringify({ lane: id }) });
        if (res && res.ok) {
          // Installed is not signed in, and the backend already knows the difference.
          toast(res.next_step
            ? (lane.label || id) + ' ' + String(res.version || '') + ' installed. ' + res.next_step
            : (lane.label || id) + ' ' + String(res.version || '') + ' installed and ready.');
        } else {
          toast('Could not install ' + (lane.label || id) + ': ' + errText(res));
        }
      } catch (e) {
        toast('Could not install ' + (lane.label || id) + ': ' + errText(e));
      }
      await refreshFleet();
      await refreshLanes();
    });
    return button;
  }

  /**
   * "Look again" — re-run discovery, including the expensive package-manager probe.
   *
   * This is the button for the case the poll cannot cover: a CLI installed AFTER the app
   * started. A GUI process keeps the PATH it was launched with, so a normal poll can miss
   * an install that a full rescan finds immediately.
   */
  async function rescanClis(button) {
    var original = button ? button.textContent : '';
    if (button) { button.disabled = true; button.textContent = 'Looking…'; }
    try {
      var data = await api('/cli/rescan', { method: 'POST', body: JSON.stringify({}) });
      state.lanes = Array.isArray(data.lanes) ? data.lanes : state.lanes;
      var found = state.lanes.filter(function (l) { return l.installed; }).length;
      toast(found ? 'Found ' + found + ' CLI' + (found === 1 ? '' : 's') + ' on this PC.' : 'No agent CLI found on this PC yet.');
      renderModels();
      await refreshLanes();
    } catch (e) {
      toast('Rescan failed: ' + errText(e));
    } finally {
      if (button) { button.disabled = false; button.textContent = original || 'Look again'; }
    }
  }

  function renderModels() {
    if (!el.subsList) return;
    el.subsList.replaceChildren();
    var lanes = state.lanes.filter(function (lane) { return String(lane.id || '') !== 'council'; });
    if (!lanes.length) {
      el.subsList.appendChild(makeEl('div', 'subs-empty', 'No models detected yet.'));
      if (el.subsSummary) el.subsSummary.textContent = '';
      return;
    }
    var on = lanes.filter(function (lane) {
      return modelEnabled(lane.id) && statusKey(lane.status) === 'ready';
    });
    if (el.subsSummary) {
      el.subsSummary.textContent = on.length + ' of ' + lanes.length + ' ready to use';
    }

    lanes.forEach(function (lane) {
      var id = String(lane.id);
      var status = statusKey(lane.status);
      var row = makeEl('div', 'subs-row');
      row.setAttribute('data-status', status);

      var dot = makeEl('span', 'subs-dot');
      dot.setAttribute('data-status', status);
      row.appendChild(dot);

      var text = makeEl('span', 'subs-text');
      var nameLine = makeEl('span', 'subs-name-line');
      nameLine.appendChild(makeEl('span', 'subs-name', lane.label || id));
      var kind = kindLabel(lane.kind);
      if (kind) nameLine.appendChild(makeEl('span', 'subs-kind', kind));
      if (lane.account) nameLine.appendChild(makeEl('span', 'subs-account', String(lane.account)));
      text.appendChild(nameLine);

      var models = Array.isArray(lane.models) ? lane.models.map(String).filter(Boolean) : [];
      if (status === 'ready' && models.length > 1) {
        // The whole point of the owner's first complaint: the models this account can
        // really run, selectable, instead of one baked-in string.
        var picker = makeEl('span', 'subs-picker');
        picker.appendChild(selectEl(
          models.map(function (m) { return { value: m, label: m }; }),
          laneModel(lane),
          function (value) { setLaneModel(id, value); },
          'Model for ' + (lane.label || id)
        ));
        picker.appendChild(makeEl('span', 'subs-count',
          models.length + ' models on this account'));
        text.appendChild(picker);
      } else {
        var detail = laneModel(lane) || String(lane.model || '');
        var line = makeEl('span', 'subs-detail', detail || 'no model reported');
        text.appendChild(line);
      }
      if (lane.reason) text.appendChild(makeEl('span', 'subs-reason', String(lane.reason)));
      // Where the binary this lane would run actually came from. On a machine that is
      // not the build host this is the difference between "we found your install" and
      // "we installed it ourselves", and the owner is entitled to know which.
      if (lane.installed && lane.command_source) {
        text.appendChild(makeEl('span', 'subs-detail',
          lane.command_source === 'skynet-managed'
            ? 'installed by Skynet'
            : 'found via ' + String(lane.command_source)));
      }
      row.appendChild(text);

      // A missing CLI is a job this app can finish, not a message to hand back.
      if (lane.can_install || lane.manual_install_url) {
        row.appendChild(installControl(lane, id));
      }

      var toggle = makeEl('button', 'subs-toggle');
      toggle.type = 'button';
      var enabled = modelEnabled(id);
      toggle.setAttribute('role', 'switch');
      toggle.setAttribute('aria-checked', enabled ? 'true' : 'false');
      toggle.setAttribute('aria-label', (enabled ? 'Disable ' : 'Enable ') + (lane.label || id));
      toggle.appendChild(makeEl('span', 'subs-toggle-knob'));
      toggle.addEventListener('click', function (ev) {
        ev.stopPropagation();
        setModelEnabled(id, !modelEnabled(id));
      });
      row.appendChild(toggle);
      el.subsList.appendChild(row);
    });

    // Installing a CLI in a terminal while this window is open cannot change this
    // process's PATH, so there has to be a way to ask the app to look again.
    var footer = makeEl('div', 'subs-row subs-row-action');
    var footerText = makeEl('span', 'subs-text');
    footerText.appendChild(makeEl('span', 'subs-detail',
      'Installed a CLI just now, or in another folder?'));
    footer.appendChild(footerText);
    var rescan = makeEl('button', 'ghost-btn', 'Look again');
    rescan.type = 'button';
    rescan.addEventListener('click', function (ev) {
      ev.stopPropagation();
      rescanClis(rescan);
    });
    footer.appendChild(rescan);
    el.subsList.appendChild(footer);

    renderLocalServers();
  }

  /* A model server already running on this machine should not require a key or a URL
     to be typed from memory; the backend probes loopback and reports what answered. */
  function renderLocalServers() {
    if (!el.localServers) return;
    el.localServers.replaceChildren();
    var servers = Array.isArray(state.localServers) ? state.localServers : [];
    el.localServers.hidden = !servers.length;
    servers.forEach(function (server) {
      var row = makeEl('div', 'local-row');
      row.appendChild(makeEl('span', 'local-dot'));
      var text = makeEl('span', 'local-text');
      text.appendChild(makeEl('span', 'local-name', String(server.label || server.id)));
      text.appendChild(makeEl('span', 'local-detail',
        'running on this machine · ' + String(server.detail || '')));
      row.appendChild(text);
      var add = makeEl('button', 'ghost-btn', 'Use it');
      add.type = 'button';
      add.addEventListener('click', function () {
        openApiForm({
          provider: 'openai-compatible',
          label: String(server.label || server.id),
          base_url: String(server.base_url || ''),
          allow_local: true,
          key: 'local',
          models: Array.isArray(server.models) ? server.models : []
        });
      });
      row.appendChild(add);
      el.localServers.appendChild(row);
    });
  }

  /* ------------------------------------------------------------- workspace */

  function renderWorkspace() {
    var ws = state.workspace;
    if (!el.workspacePath) return;
    if (!ws) {
      el.workspacePath.textContent = 'unknown';
      return;
    }
    var path = String(ws.path || '');
    el.workspacePath.textContent = path;
    el.workspacePath.title = path;
    if (el.workspaceState) {
      el.workspaceState.textContent = ws.source === 'user' ? 'chosen by you' : 'default';
    }
    if (el.workspaceFacts) {
      el.workspaceFacts.replaceChildren();
      var facts = [];
      if (ws.repo) {
        facts.push('branch ' + String(ws.branch || 'unknown'));
        var dirty = Number(ws.dirty);
        if (isFinite(dirty)) {
          facts.push(dirty === 0 ? 'no uncommitted changes'
            : dirty + (dirty === 1 ? ' uncommitted change' : ' uncommitted changes'));
        }
      } else if (ws.exists) {
        facts.push('not a git repository');
      }
      if (ws.exists && !ws.writable) facts.push('read-only');
      facts.forEach(function (fact) {
        el.workspaceFacts.appendChild(makeEl('span', 'workspace-fact', fact));
      });
    }
    if (el.workspaceWarn) {
      var warn = String(ws.warning || ws.reason || '');
      el.workspaceWarn.textContent = warn;
      el.workspaceWarn.hidden = !warn;
    }
  }

  async function applyWorkspace(path) {
    try {
      var data = await api('/workspace', { method: 'POST', body: JSON.stringify({ path: path }) });
      state.workspace = data.workspace || null;
      renderWorkspace();
      toast(path ? 'Working folder set' : 'Working folder reset');
    } catch (e) {
      toast('Folder not changed: ' + errText(e));
    }
  }

  async function pickWorkspace() {
    if (!bridge || typeof bridge.pickFolder !== 'function') {
      toast('Folder picker unavailable in this window');
      return;
    }
    var result = await bridge.pickFolder();
    if (!result || result.canceled || !result.path) return;
    await applyWorkspace(result.path);
  }

  /* -------------------------------------------------------------- api keys */

  function providerSpec(id) {
    for (var i = 0; i < state.providers.length; i += 1) {
      if (String(state.providers[i].id) === String(id)) return state.providers[i];
    }
    return null;
  }

  function renderApiKeys() {
    if (!el.apiList) return;
    el.apiList.replaceChildren();
    var keys = Array.isArray(state.apiKeys) ? state.apiKeys : [];
    if (el.apiKeysState) {
      // The two backends name the same protection differently ('dpapi_user' in the
      // Python sidecar, 'os_keystore' in the packaged runtime). Knowing only one word
      // made the packaged app under-report real encryption as "stored locally".
      var encrypted = state.encryption === 'dpapi_user' || state.encryption === 'os_keystore';
      var protection = encrypted ? 'encrypted by this PC' : 'stored locally, NOT encrypted';
      el.apiKeysState.textContent = keys.length
        ? keys.length + (keys.length === 1 ? ' key · ' : ' keys · ') + protection
        : '';
    }
    keys.forEach(function (entry) {
      var row = makeEl('div', 'api-row');
      var dot = makeEl('span', 'subs-dot');
      dot.setAttribute('data-status', entry.verified ? 'ready' : 'unavailable');
      row.appendChild(dot);

      var text = makeEl('span', 'subs-text');
      var nameLine = makeEl('span', 'subs-name-line');
      nameLine.appendChild(makeEl('span', 'subs-name', String(entry.label || entry.provider_label)));
      // A local model server is not a subscription key. Advisor review flagged the badge
      // "API KEY / olla…ocal" as mislabelling Ollama and hiding the useful fact — which
      // is the endpoint, not a masked secret nobody needs to recognise.
      var local = !!entry.allow_local;
      nameLine.appendChild(makeEl('span', 'subs-kind', local ? 'Local' : 'API key'));
      nameLine.appendChild(makeEl('span', 'subs-account',
        local ? String(entry.base_url || '') : String(entry.key_hint || '')));
      text.appendChild(nameLine);

      var models = Array.isArray(entry.models) ? entry.models.map(String) : [];
      if (entry.verified && models.length) {
        var picker = makeEl('span', 'subs-picker');
        picker.appendChild(selectEl(
          models.map(function (m) { return { value: m, label: m }; }),
          String(entry.model || ''),
          function (value) { setApiKeyModel(entry.id, value); },
          'Model for ' + String(entry.label || entry.provider_label)
        ));
        picker.appendChild(makeEl('span', 'subs-count', models.length + ' models on this key'));
        text.appendChild(picker);
      } else {
        text.appendChild(makeEl('span', 'subs-reason',
          String(entry.detail || 'this key has not been verified yet')));
      }
      row.appendChild(text);

      var retest = makeEl('button', 'ghost-btn', 'Re-test');
      retest.type = 'button';
      retest.addEventListener('click', function () { retestApiKey(entry); });
      row.appendChild(retest);

      var remove = makeEl('button', 'ghost-btn danger', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', function () { removeApiKey(entry); });
      row.appendChild(remove);

      el.apiList.appendChild(row);
    });
  }

  function renderProviderOptions() {
    if (!el.apiProvider) return;
    el.apiProvider.replaceChildren();
    state.providers.forEach(function (provider) {
      var option = makeEl('option', null, String(provider.label));
      option.value = String(provider.id);
      el.apiProvider.appendChild(option);
    });
  }

  function syncApiFormProvider() {
    var spec = providerSpec(el.apiProvider ? el.apiProvider.value : '');
    var needsBase = !!(spec && spec.needs_base_url);
    if (el.apiBaseWrap) el.apiBaseWrap.hidden = !needsBase;
    if (el.apiLocalWrap) el.apiLocalWrap.hidden = !needsBase;
    if (el.apiBaseUrl && !needsBase && spec) el.apiBaseUrl.value = String(spec.base_url || '');
  }

  function openApiForm(prefill) {
    var data = prefill || {};
    state.apiFormOpen = true;
    state.apiEditingId = '';
    state.apiTested = null;
    if (el.apiForm) el.apiForm.hidden = false;
    if (el.apiAdd) el.apiAdd.hidden = true;
    renderProviderOptions();
    if (el.apiProvider && data.provider) el.apiProvider.value = String(data.provider);
    if (el.apiLabel) el.apiLabel.value = String(data.label || '');
    if (el.apiBaseUrl) el.apiBaseUrl.value = String(data.base_url || '');
    if (el.apiAllowLocal) el.apiAllowLocal.checked = !!data.allow_local;
    if (el.apiKey) el.apiKey.value = data.key === 'local' ? 'local' : '';
    if (el.apiVerdict) { el.apiVerdict.hidden = true; el.apiVerdict.textContent = ''; }
    if (el.apiModelWrap) el.apiModelWrap.hidden = true;
    syncApiFormProvider();
    if (el.apiKey) el.apiKey.focus();
  }

  function closeApiForm() {
    state.apiFormOpen = false;
    state.apiTested = null;
    if (el.apiForm) el.apiForm.hidden = true;
    if (el.apiAdd) el.apiAdd.hidden = false;
    if (el.apiKey) el.apiKey.value = '';
  }

  function apiVerdict(message, ok) {
    if (!el.apiVerdict) return;
    el.apiVerdict.textContent = String(message);
    el.apiVerdict.hidden = false;
    el.apiVerdict.classList.toggle('is-ok', !!ok);
    el.apiVerdict.classList.toggle('is-bad', !ok);
  }

  function apiFormPayload() {
    return {
      provider: el.apiProvider ? el.apiProvider.value : '',
      key: el.apiKey ? el.apiKey.value : '',
      base_url: el.apiBaseUrl ? el.apiBaseUrl.value : '',
      label: el.apiLabel ? el.apiLabel.value : '',
      allow_local: !!(el.apiAllowLocal && el.apiAllowLocal.checked)
    };
  }

  /* A key is called working only after the provider itself answered with a model list.
     Typing something into a box is not evidence that a model will reply. */
  async function testApiKey() {
    var payload = apiFormPayload();
    if (!payload.key) { apiVerdict('Paste the key first.', false); return; }
    apiVerdict('Asking the provider…', true);
    if (el.apiTest) el.apiTest.disabled = true;
    try {
      var data = await api('/apikeys/test', { method: 'POST', body: JSON.stringify(payload) });
      state.apiTested = data;
      apiVerdict(String(data.detail || 'the provider accepted this key'), !!data.ok);
      var models = Array.isArray(data.models) ? data.models.map(String) : [];
      if (el.apiModel && models.length) {
        el.apiModel.replaceChildren();
        models.forEach(function (model) {
          var option = makeEl('option', null, model);
          option.value = model;
          el.apiModel.appendChild(option);
        });
        if (el.apiModelWrap) el.apiModelWrap.hidden = false;
      }
    } catch (e) {
      state.apiTested = null;
      apiVerdict(errText(e), false);
    } finally {
      if (el.apiTest) el.apiTest.disabled = false;
    }
  }

  async function saveApiKey() {
    var payload = apiFormPayload();
    if (!payload.key) { apiVerdict('Paste the key first.', false); return; }
    if (el.apiModel && el.apiModelWrap && !el.apiModelWrap.hidden) {
      payload.model = el.apiModel.value;
    }
    if (el.apiSave) el.apiSave.disabled = true;
    try {
      var data = await api('/apikeys', { method: 'POST', body: JSON.stringify(payload) });
      if (!data.ok) {
        apiVerdict(String(data.detail || 'the provider did not accept this key'), false);
        return;
      }
      closeApiForm();
      toast('API key saved');
      await refreshFleet();
    } catch (e) {
      apiVerdict(errText(e), false);
    } finally {
      if (el.apiSave) el.apiSave.disabled = false;
    }
  }

  async function retestApiKey(entry) {
    try {
      var data = await api('/apikeys', {
        method: 'POST',
        body: JSON.stringify({
          id: entry.id, provider: entry.provider, base_url: entry.base_url,
          label: entry.label, allow_local: entry.allow_local
        })
      });
      toast(data.ok ? 'Key still works' : ('Key failed: ' + String(data.detail || 'unknown')));
      await refreshFleet();
    } catch (e) {
      toast('Re-test failed: ' + errText(e));
    }
  }

  async function setApiKeyModel(id, model) {
    try {
      await api('/apikeys/model', { method: 'POST', body: JSON.stringify({ id: id, model: model }) });
      await refreshFleet();
    } catch (e) {
      toast('Model not changed: ' + errText(e));
    }
  }

  async function removeApiKey(entry) {
    try {
      await api('/apikeys/remove', { method: 'POST', body: JSON.stringify({ id: entry.id }) });
      toast('API key removed');
      await refreshFleet();
    } catch (e) {
      toast('Could not remove the key: ' + errText(e));
    }
  }

  /* ------------------------------------------------------------ fleet roles */

  function openSettings() {
    if (!el.settings) return;
    // The route popover left open behind the drawer collides with it (advisor review of
    // the shipped screenshots, 2026-08-05). One surface at a time.
    closeLanePop();
    renderModels();
    renderApiKeys();
    renderWorkspace();
    renderOrchestration();
    el.settings.hidden = false;
    if (el.settingsScrim) el.settingsScrim.hidden = false;
    refreshFleet();
  }

  function closeSettings() {
    if (el.settings) el.settings.hidden = true;
    if (el.settingsScrim) el.settingsScrim.hidden = true;
    closeApiForm();
  }

  function saveOrchestration() {
    try {
      window.localStorage.setItem('skynet.orchestration.v2', JSON.stringify(state.orchestration));
    } catch (e) { /* local preference persistence is optional */ }
  }

  function asRow(value) {
    if (!value) return null;
    if (typeof value === 'string') return { lane: value, model: '' };
    if (typeof value === 'object' && value.lane) {
      return { lane: String(value.lane), model: String(value.model || '') };
    }
    return null;
  }

  function asRows(list) {
    return (Array.isArray(list) ? list : []).map(asRow).filter(Boolean);
  }

  function loadOrchestration() {
    var raw = null;
    try {
      raw = window.localStorage.getItem('skynet.orchestration.v2') ||
            window.localStorage.getItem('skynet.orchestration.v1');
    } catch (e) { return; }
    if (!raw) return;
    try {
      var parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return;
      state.orchestration.enabled = !!parsed.enabled;
      state.orchestration.orchestrator = asRow(parsed.orchestrator);
      state.orchestration.workers = asRows(parsed.workers);
      state.orchestration.advisors = asRows(parsed.advisors);
    } catch (e2) { /* corrupt preference is ignored, never treated as fleet truth */ }
  }

  /* Rows may repeat; what they may NOT do is point at a lane that is gone or off. */
  function sanitizeOrchestration() {
    var execById = {};
    orchestrationCandidates().forEach(function (lane) { execById[String(lane.id)] = lane; });
    var reviewById = {};
    advisorCandidates().forEach(function (lane) { reviewById[String(lane.id)] = lane; });
    var o = state.orchestration;

    function keep(pool) {
      return function (row) { return row && pool[row.lane]; };
    }
    if (o.orchestrator && !execById[o.orchestrator.lane]) o.orchestrator = null;
    o.workers = o.workers.filter(keep(execById));
    o.advisors = o.advisors.filter(keep(reviewById));

    var ids = Object.keys(execById);
    if (o.enabled) {
      if (!o.orchestrator && ids.length) {
        o.orchestrator = { lane: ids[0], model: laneModel(execById[ids[0]]) };
      }
      if (!o.workers.length && o.orchestrator) {
        // One worker seeded on the SAME lane as the orchestrator is legal now, and is
        // the honest default when only one execution lane is signed in.
        var seed = ids.filter(function (id) { return id !== o.orchestrator.lane; })[0] ||
                   o.orchestrator.lane;
        o.workers = [{ lane: seed, model: laneModel(execById[seed]) }];
      }
      if (!o.orchestrator || !o.workers.length) o.enabled = false;
    }
    saveOrchestration();
  }

  function roleRow(row, index, role, pool) {
    var wrap = makeEl('div', 'role-row');
    var lane = pool[row.lane];
    var status = lane ? statusKey(lane.status) : 'unknown';

    var dot = makeEl('span', 'subs-dot');
    dot.setAttribute('data-status', status);
    wrap.appendChild(dot);

    var laneOptions = Object.keys(pool).map(function (id) {
      return { value: id, label: pool[id].label || id };
    });
    wrap.appendChild(selectEl(laneOptions, row.lane, function (value) {
      row.lane = value;
      row.model = laneModel(pool[value] || { id: value });
      saveOrchestration();
      renderOrchestration();
    }, role + ' lane ' + (index + 1)));

    var models = lane && Array.isArray(lane.models) ? lane.models.map(String).filter(Boolean) : [];
    if (models.length > 1) {
      wrap.appendChild(selectEl(
        models.map(function (m) { return { value: m, label: m }; }),
        row.model || laneModel(lane),
        function (value) { row.model = value; saveOrchestration(); renderOrchestration(); },
        role + ' model ' + (index + 1)
      ));
    } else {
      wrap.appendChild(makeEl('span', 'role-row-model',
        row.model || (lane ? laneModel(lane) : '') || 'default model'));
    }

    var spacer = makeEl('span', 'role-row-spacer');
    wrap.appendChild(spacer);

    if (role !== 'orchestrator') {
      var dup = makeEl('button', 'icon-btn', '⧉');
      dup.type = 'button';
      dup.title = 'Duplicate this row';
      dup.setAttribute('aria-label', 'Duplicate ' + role + ' row ' + (index + 1));
      dup.addEventListener('click', function () {
        var list = role === 'worker' ? state.orchestration.workers : state.orchestration.advisors;
        list.splice(index + 1, 0, { lane: row.lane, model: row.model });
        saveOrchestration();
        renderOrchestration();
      });
      wrap.appendChild(dup);

      var remove = makeEl('button', 'icon-btn', '×');
      remove.type = 'button';
      remove.title = 'Remove this row';
      remove.setAttribute('aria-label', 'Remove ' + role + ' row ' + (index + 1));
      remove.addEventListener('click', function () {
        var list = role === 'worker' ? state.orchestration.workers : state.orchestration.advisors;
        list.splice(index, 1);
        sanitizeOrchestration();
        renderOrchestration();
      });
      wrap.appendChild(remove);
    }
    return wrap;
  }

  function renderRoleRows(target, rows, role, pool, emptyText) {
    if (!target) return;
    target.replaceChildren();
    if (!rows.length) {
      target.appendChild(makeEl('div', 'role-empty', emptyText));
      return;
    }
    rows.forEach(function (row, index) {
      target.appendChild(roleRow(row, index, role, pool));
    });
  }

  /* Honest about what "3 workers" buys you: a lane that runs one job at a time will
     run them one after another, however many rows point at it. */
  function contentionNote(rows, pool) {
    var counts = {};
    rows.forEach(function (row) {
      counts[row.lane] = (counts[row.lane] || 0) + 1;
    });
    var notes = [];
    Object.keys(counts).forEach(function (id) {
      var lane = pool[id];
      var limit = lane && Number(lane.concurrency) > 0 ? Number(lane.concurrency) : 1;
      if (counts[id] > limit) {
        notes.push(counts[id] + ' rows share ' + ((lane && lane.label) || id) +
          ', which runs ' + (limit === 1 ? 'one at a time' : limit + ' at a time') +
          ' — they queue.');
      }
    });
    return notes.join(' ');
  }

  function renderOrchestration() {
    var o = state.orchestration;
    var execById = {};
    orchestrationCandidates().forEach(function (lane) { execById[String(lane.id)] = lane; });
    var reviewById = {};
    advisorCandidates().forEach(function (lane) { reviewById[String(lane.id)] = lane; });

    if (el.orchestrationToggle) el.orchestrationToggle.checked = !!o.enabled;
    if (el.orchestrationState) el.orchestrationState.textContent = o.enabled ? 'On' : 'Off';
    if (el.roleBoard) el.roleBoard.hidden = !o.enabled;
    if (el.orchestrationNote) {
      el.orchestrationNote.textContent = Object.keys(execById).length < 1
        ? 'No execution model is ready. Sign in to a CLI lane or add an API key above.'
        : 'Every row is its own run, so the same model can fill as many rows as you want. Workers answer first; the orchestrator writes the final answer from their results.';
    }

    renderRoleRows(el.orchestratorRows, o.orchestrator ? [o.orchestrator] : [],
      'orchestrator', execById, 'No execution model is ready.');
    renderRoleRows(el.workerRows, o.workers, 'worker', execById, 'No workers yet.');
    renderRoleRows(el.advisorRows, o.advisors, 'validator', reviewById,
      'None. Validators are optional.');

    if (el.workerAdd) el.workerAdd.disabled = !Object.keys(execById).length;
    if (el.advisorAdd) el.advisorAdd.disabled = !Object.keys(reviewById).length;
    if (el.workerContention) {
      var note = contentionNote(o.workers, execById);
      el.workerContention.textContent = note;
      el.workerContention.hidden = !note;
    }
  }

  function addRoleRow(role) {
    var pool = role === 'worker' ? orchestrationCandidates() : advisorCandidates();
    if (!pool.length) return;
    var list = role === 'worker' ? state.orchestration.workers : state.orchestration.advisors;
    var last = list.length ? list[list.length - 1] : null;
    // Duplicating the previous row is the common case (same model, more of it), so a
    // new row copies it instead of resetting to a lane the owner did not choose.
    var seed = last ? { lane: last.lane, model: last.model }
                    : { lane: String(pool[0].id), model: laneModel(pool[0]) };
    list.push(seed);
    saveOrchestration();
    renderOrchestration();
  }

  /* Everything the panel shows comes from one read, so lanes, keys, folder and roles
     can never disagree with each other on screen. */
  async function refreshFleet() {
    try {
      var data = await api('/models');
      state.lanes = Array.isArray(data.lanes) ? data.lanes : [];
      state.apiKeys = Array.isArray(data.api_keys) ? data.api_keys : [];
      state.providers = Array.isArray(data.providers) ? data.providers : [];
      state.localServers = Array.isArray(data.local_servers) ? data.local_servers : [];
      state.workspace = data.workspace || null;
      state.encryption = String(data.encryption || '');
      // Populate the provider list on every load, not only when the form is opened:
      // a form opened before the first /models answer would offer an empty dropdown.
      renderProviderOptions();
      if (state.apiFormOpen) syncApiFormProvider();
      if (data.active) {
        state.activeLane = data.active;
        var active = laneById(data.active);
        if (active && active.model) state.activeModel = laneModel(active);
      }
      sanitizeOrchestration();
      renderModels();
      renderApiKeys();
      renderWorkspace();
      renderOrchestration();
      renderLanePop();
      paintLane();
      // A fresh install on a machine with no CLI signed in has NO usable model. Saying so
      // up front beats letting the first message come back "provider unavailable".
      var usable = state.lanes.filter(function (lane) {
        return statusKey(lane.status) === 'ready' && modelEnabled(lane.id) && lane.id !== 'council';
      });
      if (!usable.length) {
        showBanner('No model is ready on this PC yet. Open Models & fleet to add an API key, ' +
                   'point at a local model server, or sign in to the Codex or Claude CLI.',
                   'NO MODEL');
      } else {
        hideBanner();
      }
      return true;
    } catch (e) {
      // Fall back to the narrow lane list rather than blanking the panel: a missing
      // models surface must not read as "no models exist".
      await refreshLanes();
      return false;
    }
  }

  function renderLanePop() {
    if (!el.lanePopList) return;
    el.lanePopList.replaceChildren();

    MODES.forEach(function (mode) {
      var route = laneById(mode.provider);
      var status = route ? statusKey(route.status) : 'unknown';
      var row = makeEl('button', 'lane-row mode-row');
      row.type = 'button';
      if (mode.id === state.activeMode) row.classList.add('is-active');
      if (status !== 'ready') row.classList.add('is-off');
      var g = makeEl('span', 'lane-row-glyph', glyphFor(status));
      g.setAttribute('data-status', status);
      row.appendChild(g);
      var textWrap = makeEl('span', 'lane-row-text');
      textWrap.appendChild(makeEl('span', 'lane-row-label', mode.label));
      textWrap.appendChild(makeEl('span', 'lane-row-meta', mode.detail));
      row.appendChild(textWrap);
      row.appendChild(makeEl('span', 'lane-row-status', mode.provider));
      row.addEventListener('click', function () { pickMode(mode); });
      el.lanePopList.appendChild(row);
    });

    var advanced = makeEl('button', 'advanced-toggle',
      state.advancedOpen ? 'Hide advanced routes' : 'Advanced routes');
    advanced.type = 'button';
    advanced.addEventListener('click', function () {
      state.advancedOpen = !state.advancedOpen;
      renderLanePop();
    });
    el.lanePopList.appendChild(advanced);

    if (!state.advancedOpen) return;
    if (!state.lanes.length) {
      el.lanePopList.appendChild(makeEl('div', 'side-note', 'No routes reported by the sidecar.'));
      return;
    }

    state.lanes.forEach(function (lane) {
      var status = statusKey(lane.status);
      var row = makeEl('button', 'lane-row advanced-row');
      row.type = 'button';
      if (String(lane.id) === String(state.activeLane)) row.classList.add('is-active');
      if (status !== 'ready') row.classList.add('is-off');

      var g = makeEl('span', 'lane-row-glyph', glyphFor(status));
      g.setAttribute('data-status', status);
      row.appendChild(g);

      var textWrap = makeEl('span', 'lane-row-text');
      textWrap.appendChild(makeEl('span', 'lane-row-label', lane.label || lane.id));
      textWrap.appendChild(makeEl('span', 'lane-row-meta',
        String(lane.id) + (lane.model ? '  \u00B7  ' + lane.model : '')));
      row.appendChild(textWrap);

      var st = makeEl('span', 'lane-row-status', status);
      st.setAttribute('data-status', status);
      row.appendChild(st);

      row.addEventListener('click', function () { pickLane(lane); });
      el.lanePopList.appendChild(row);
    });
  }

  /* A response mode is a PREFERENCE, not an override.
     Owner, 2026-08-05: "response mode should not override what the user created if its
     only one". Modes like Best/Research ask for a merged multi-model answer; if this
     machine only has one usable model, the honest route is that one model, not a
     council that cannot convene. This resolves the mode against what actually exists. */
  function resolveModeRoute(mode) {
    var wanted = laneById(mode.provider);
    if (wanted && statusKey(wanted.status) === 'ready' && modelEnabled(wanted.id)) return wanted;
    var usable = orchestrationCandidates();
    if (!usable.length) return wanted || null;
    if (usable.length === 1) return usable[0];
    // More than one exists but the mode's own route is down: prefer the active lane.
    var active = laneById(state.activeLane);
    if (active && statusKey(active.status) === 'ready' && modelEnabled(active.id)) return active;
    return usable[0];
  }

  async function pickMode(mode) {
    state.activeMode = mode.id;
    var route = resolveModeRoute(mode);
    if (!route) {
      toast('No model is ready for that mode yet.');
      return;
    }
    if (String(route.id) !== String(mode.provider)) {
      toast(mode.label + ' needs more than one model, so this runs on ' +
            (route.label || route.id) + '.');
    }
    await pickProvider(route.id, laneModel(route), mode.label);
  }

  function openLanePop() {
    if (!el.lanePop) return;
    el.lanePop.hidden = false;
    if (el.laneChip) el.laneChip.setAttribute('aria-expanded', 'true');
    renderLanePop();
    refreshFleet();
  }

  function closeLanePop() {
    if (!el.lanePop) return;
    el.lanePop.hidden = true;
    if (el.laneChip) el.laneChip.setAttribute('aria-expanded', 'false');
  }

  function toggleLanePop() {
    if (!el.lanePop) return;
    if (el.lanePop.hidden) openLanePop(); else closeLanePop();
  }

  async function pickProvider(provider, model, displayLabel) {
    closeLanePop();
    var prevLane = state.activeLane;
    var prevModel = state.activeModel;

    state.activeLane = provider;
    state.activeModel = model || null;
    paintLane();

    var body = { provider: provider };
    if (state.sessionId) body.session_id = state.sessionId;
    if (model) body.model = model;

    try {
      var res = await api('/provider', { method: 'POST', body: JSON.stringify(body) });
      state.activeLane = res.provider || provider;
      state.activeModel = res.model || model || null;
      state.pendingProvider = state.activeLane;
      state.pendingModel = state.activeModel;
      paintLane();
      toast((displayLabel || provider) + ' selected');
    } catch (e) {
      /* keep the pick locally and pass it on the next /chat rather than lying */
      state.pendingProvider = provider;
      state.pendingModel = model || null;
      state.activeLane = prevLane || provider;
      state.activeModel = prevModel || model || null;
      paintLane();
      toast('Selection not persisted: ' + errText(e));
    }
  }

  async function pickLane(lane) {
    state.activeMode = 'advanced';
    if (state.orchestration.enabled) {
      // Say it instead of accepting a click that changes nothing about the answer.
      toast('Fleet roles is on, so the orchestrator answers. Turn it off to pick a route.');
      closeLanePop();
      return;
    }
    await pickProvider(lane.id, laneModel(lane) || lane.model || null, lane.label || lane.id);
  }

  async function refreshLanes() {
    try {
      var data = await api('/lanes');
      state.lanes = Array.isArray(data.lanes) ? data.lanes : [];
      if (data.active) {
        state.activeLane = data.active;
        var active = laneById(data.active);
        if (active && active.model) state.activeModel = active.model;
      } else if (!state.activeLane && state.lanes.length) {
        var flagged = state.lanes.filter(function (l) { return l.active; })[0];
        if (flagged) {
          state.activeLane = flagged.id;
          state.activeModel = flagged.model || null;
        }
      }
      if (el.lanePopSub) {
        // Design review, round 1: "N routes - live status" made the user reconcile four
        // outcome modes against a route count. Surface only what needs action.
        var unhealthy = state.lanes.filter(function (l) { return statusKey(l.status) !== 'ready'; });
        el.lanePopSub.textContent = unhealthy.length ? unhealthy.length + ' need attention' : '';
      }
      paintLane();
      sanitizeOrchestration();
      renderOrchestration();
      if (el.lanePop && !el.lanePop.hidden) renderLanePop();
    } catch (e) {
      if (el.lanePopSub) el.lanePopSub.textContent = 'status unknown';
      paintLane();
    }
  }

  /* ==========================================================================
     SESSIONS
     ========================================================================== */

  function renderSessions() {
    if (!el.sessionList) return;
    el.sessionList.replaceChildren();

    if (!state.sessions.length) {
      el.sessionList.appendChild(makeEl('div', 'side-note',
        'No sessions yet. Start one with New chat.'));
      return;
    }

    state.sessions.forEach(function (s) {
      var btn = makeEl('button', 'session');
      btn.type = 'button';
      if (String(s.id) === String(state.sessionId)) btn.classList.add('is-active');

      var title = (s.title === null || s.title === undefined || s.title === '')
        ? '(empty)' : String(s.title);
      btn.appendChild(makeEl('span', 'session-title', title));

      var bits = [];
      var rel = relTime(s.updated_at);
      if (rel) bits.push(rel);
      if (typeof s.messages === 'number') {
        bits.push(s.messages + (s.messages === 1 ? ' msg' : ' msgs'));
      }
      btn.appendChild(makeEl('span', 'session-meta', bits.join('  \u00B7  ')));
      btn.title = title;

      btn.addEventListener('click', function () { openSession(s.id); });
      el.sessionList.appendChild(btn);
    });
  }

  async function refreshSessions() {
    try {
      var data = await api('/sessions?limit=50');
      state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
      renderSessions();
    } catch (e) {
      if (el.sessionList) {
        el.sessionList.replaceChildren();
        el.sessionList.appendChild(makeEl('div', 'side-note',
          'Sessions unavailable: ' + errText(e)));
      }
    }
  }

  async function openSession(id) {
    if (state.streaming) {
      toast('Still streaming - stop the current turn first.');
      return;
    }
    closeNav();
    try {
      var data = await api('/session?id=' + encodeURIComponent(id));
      state.sessionId = data.id || id;

      if (data.provider) state.activeLane = data.provider;
      if (data.model) state.activeModel = data.model;
      if (data.provider === 'council' && state.activeMode !== 'research') state.activeMode = 'best';
      if (data.provider === 'codex' && state.activeMode !== 'code') state.activeMode = 'fast';
      state.pendingProvider = null;
      state.pendingModel = null;
      paintLane();

      el.turns.replaceChildren();
      var messages = Array.isArray(data.messages) ? data.messages : [];
      if (!messages.length) {
        setEmptyVisible(true);
      } else {
        setEmptyVisible(false);
        messages.forEach(function (m) {
          var role = String(m.role || '').toLowerCase();
          if (role === 'user') {
            addUserTurn(m.content, m.ts);
          } else {
            var handle = addAssistantTurn({ withThinking: false, ts: m.ts });
            mountMarkdown(handle.md, m.content);
          }
        });
      }
      renderSessions();
      scrollToBottom(true);
    } catch (e) {
      toast('Could not open session: ' + errText(e));
    }
  }

  function newChat() {
    if (state.streaming) {
      toast('Still streaming - stop the current turn first.');
      return;
    }
    state.sessionId = null;
    // A route the owner chose explicitly survives a new chat. Resetting it to the mode's
    // default was the same override in another place: you pick a model, start a new
    // chat, and silently get something else.
    if (state.activeMode === 'advanced' && state.activeLane) {
      state.pendingProvider = state.activeLane;
      state.pendingModel = state.activeModel || null;
    } else {
      var route = resolveModeRoute(modeById(state.activeMode));
      state.pendingProvider = route ? route.id : null;
      state.pendingModel = route ? laneModel(route) : null;
    }
    clearTranscript();
    renderSessions();
    closeNav();
    if (el.input) el.input.focus();
  }

  /* ==========================================================================
     HEALTH
     ========================================================================== */

  /* ==========================================================================
     SUPPORT CARD — at most once per calendar day
     ========================================================================== */

  var SUPPORT_SEEN_KEY = 'skynet.support.lastShownDay';

  /* A LOCAL calendar day, not a UTC one and not a rolling 24h window. `toISOString()`
     would roll over mid-evening for anyone west of UTC, showing the card twice in one
     of their days; a rolling window drifts later each time until it lands mid-session. */
  function localDayStamp(now) {
    var d = now || new Date();
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' +
           String(d.getDate()).padStart(2, '0');
  }

  function supportCardDue(today, lastShown) {
    // Never seen -> due. Seen on a different day -> due. Seen today -> not due.
    return !lastShown || lastShown !== today;
  }

  function readSupportLastShown() {
    try {
      return window.localStorage.getItem(SUPPORT_SEEN_KEY);
    } catch (e) {
      // Storage can be unavailable or full. Treat that as "already shown" rather than
      // showing on every launch -- a sponsorship ask that cannot remember being dismissed
      // is worse than one that is occasionally missed.
      return localDayStamp();
    }
  }

  function markSupportShown(today) {
    try {
      window.localStorage.setItem(SUPPORT_SEEN_KEY, today);
    } catch (e) { /* non-fatal: worst case it shows again next launch */ }
  }

  function dismissSupportCard() {
    if (el.supportCard) el.supportCard.hidden = true;
  }

  function renderSupportCard() {
    var card = el.supportCard;
    if (!card) return;
    var today = localDayStamp();
    if (!supportCardDue(today, readSupportLastShown())) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    markSupportShown(today);
  }

  /* Show WHICH bytes are running. The version string alone is not an answer: two payloads
     once shipped as "0.1.1" with different app.asar hashes, so a crash report could not be
     mapped to code. buildId is content-derived, so it is unique per payload. A build made
     from an uncommitted tree is marked, because its commit does not vouch for its bytes. */
  function renderBuildIdentity() {
    var node = el.tbAppBuild;
    if (!node) return;
    var id = String(bridge.buildId || '');
    if (!id) {
      // Unstamped dev run. Say nothing rather than imply a released build.
      node.hidden = true;
      node.textContent = '';
      return;
    }
    var dirty = bridge.sourceMembersClean !== true;
    node.hidden = false;
    node.textContent = id;
    node.classList.toggle('is-dirty', dirty);
    var detail = ['build ' + id];
    if (bridge.sourceCommit) detail.push('commit ' + String(bridge.sourceCommit).slice(0, 12));
    if (bridge.sourceDigest) detail.push('payload ' + String(bridge.sourceDigest).slice(0, 16));
    detail.push(dirty ? 'built from an UNCOMMITTED tree' : 'built from a clean tree');
    node.title = detail.join('\n');
  }

  async function refreshHealth() {
    if (!HAS_BRIDGE || typeof bridge.api !== 'function' || !bridge.backendReady) {
      showBanner('No sidecar bridge on window.skynet - the renderer is running ' +
                 'outside the Electron shell, so no lane can answer.');
      if (el.tbBuild) el.tbBuild.textContent = 'desktop \u00B7 no bridge';
      return;
    }
    try {
      var data = await api('/health');
      hideBanner();
      var bits = [];
      if (data.build_id) bits.push(String(data.build_id));
      if (data.pid) bits.push('pid ' + data.pid);
      if (el.tbBuild) el.tbBuild.textContent = bits.length ? bits.join('  \u00B7  ') : 'desktop';
      if (data.repl_ok === false) {
        showBanner('Skynet REPL did not import: ' + (data.detail || 'no detail reported'));
      }
    } catch (e) {
      var detail = (e && e.data && e.data.detail) ? e.data.detail : errText(e);
      showBanner('Sidecar not healthy: ' + detail);
      if (el.tbBuild) el.tbBuild.textContent = 'desktop \u00B7 sidecar down';
    }
  }

  /* ==========================================================================
     STREAMING  -  fetch + ReadableStream, NOT EventSource (no auth header there)
     ========================================================================== */

  function parseFrame(raw) {
    var event = 'message';
    var dataLines = [];
    var lines = raw.split('\n');
    for (var i = 0; i < lines.length; i += 1) {
      var line = lines[i].replace(/\r$/, '');
      if (!line || line.charAt(0) === ':') continue;
      var idx = line.indexOf(':');
      var field, value;
      if (idx === -1) { field = line; value = ''; }
      else {
        field = line.slice(0, idx);
        value = line.slice(idx + 1);
        if (value.charAt(0) === ' ') value = value.slice(1);
      }
      if (field === 'event') event = value;
      else if (field === 'data') dataLines.push(value);
    }
    var text = dataLines.join('\n');
    var payload = null;
    if (text) { try { payload = JSON.parse(text); } catch (e) { payload = { text: text }; } }
    return { event: event, data: payload || {}, raw: text };
  }

  function setStreaming(on) {
    state.streaming = on;
    // Cancellation is intentionally absent until the backend can terminate the
    // actual agent process tree. Hiding a fetch abort behind "Stop" would be false.
    if (el.stopBtn) el.stopBtn.hidden = true;
    if (el.sendBtn) {
      el.sendBtn.hidden = false;
      el.sendBtn.disabled = on || !el.input || !el.input.value.trim();
    }
    if (el.input) el.input.disabled = false;
  }

  function turnError(handle, message) {
    if (handle && handle.md) {
      handle.md.replaceChildren();
      handle.md.appendChild(makeEl('div', 'turn-error', message));
    }
  }

  function turnNote(handle, message) {
    if (handle && handle.md) {
      handle.md.replaceChildren();
      handle.md.appendChild(makeEl('div', 'turn-note', message));
    }
  }

  function doneSummary(d, handle) {
    var who = [];
    if (d.lane) who.push(String(d.lane));
    if (d.provider && String(d.provider) !== String(d.lane)) who.push(String(d.provider));
    var label = who.length ? who.join('/') : 'lane unknown';
    var bits = [label];
    var secs = fmtSeconds(d.duration_ms);
    if (secs) bits.push(secs);
    if (d.classification) bits.push(String(d.classification));
    if (handle && handle.phases.length) {
      bits.push(handle.phases.length + (handle.phases.length === 1 ? ' step' : ' steps'));
    }
    return bits.join(' \u00B7 ');
  }

  async function send(rawText) {
    if (state.streaming) return;
    var text = String(rawText || '').trim();
    if (!text) return;

    closeLanePop();
    if (el.input) {
      el.input.value = '';
      autoGrow();
    }

    addUserTurn(text, Date.now());
    var handle = addAssistantTurn({ withThinking: true, ts: Date.now() });
    state.live = handle;

    setStreaming(true);

    var payload = { text: text };
    if (state.sessionId) payload.session_id = state.sessionId;
    if (state.pendingProvider) {
      payload.provider = state.pendingProvider;
      if (state.pendingModel) payload.model = state.pendingModel;
    }
    function roleRows(list) {
      return (list || []).map(function (row) {
        return { lane: String(row.lane), model: String(row.model || '') };
      });
    }
    payload.orchestration = {
      enabled: !!state.orchestration.enabled,
      orchestrator: state.orchestration.orchestrator
        ? { lane: String(state.orchestration.orchestrator.lane),
            model: String(state.orchestration.orchestrator.model || '') }
        : null,
      workers: roleRows(state.orchestration.workers),
      worker_count: state.orchestration.workers.length,
      advisors: roleRows(state.orchestration.advisors)
    };

    var sawDone = false;
    var sawError = false;
    var deltaBuffer = '';

    function handleFrame(frame) {
      var d = frame.data || {};
      if (frame.event === 'start') {
        if (d.session_id) state.sessionId = d.session_id;
        if (d.provider) state.activeLane = d.provider;
        if (d.model) state.activeModel = d.model;
        paintLane();
        addPhase(handle, {
          phase: 'start',
          lane: d.provider || '',
          text: d.model ? String(d.model) : ''
        });
      } else if (frame.event === 'phase') {
        addPhase(handle, d);
      } else if (frame.event === 'delta') {
        var fragment = (d.text === null || d.text === undefined) ? '' : String(d.text);
        if (fragment) {
          deltaBuffer += fragment;
          mountMarkdown(handle.md, deltaBuffer);
          scrollToBottom(false);
        }
      } else if (frame.event === 'done') {
        sawDone = true;
        if (d.session_id) state.sessionId = d.session_id;
        if (d.provider) state.activeLane = d.provider;
        if (d.model) state.activeModel = d.model;
        paintLane();

        var content = (d.content === null || d.content === undefined) ? '' : String(d.content);
        if (content.trim() && content !== deltaBuffer) {
          mountMarkdown(handle.md, content);
        } else if (content.trim()) {
          deltaBuffer = content;
        } else if (d.ok === false) {
          turnError(handle, 'The lane returned no content. ok=false' +
                            (d.classification ? ' (' + d.classification + ')' : ''));
        } else {
          turnNote(handle, 'The lane finished but returned empty content.');
        }
        finishThinking(handle, doneSummary(d, handle), d.ok === false ? 'error' : 'done');
        state.pendingProvider = null;
        state.pendingModel = null;
      } else if (frame.event === 'error') {
        sawError = true;
        var msg = d.error ? String(d.error) : (frame.raw || 'unknown error');
        turnError(handle, msg);
        finishThinking(handle, 'error \u00B7 ' + fmtSeconds(Date.now() - handle.startedAt), 'error');
      }
    }

    try {
      if (!bridge || typeof bridge.chat !== 'function') throw new Error('chat bridge unavailable');
      var result = await bridge.chat(payload, handleFrame);
      if (!result || !result.ok) {
        throw new Error(String((result && result.error) || 'sidecar chat failed'));
      }

      if (!sawDone && !sawError) {
        turnNote(handle, 'The stream closed without a done frame - the answer is UNKNOWN.');
        finishThinking(handle, 'stream ended early \u00B7 ' +
          fmtSeconds(Date.now() - handle.startedAt), 'error');
      }
    } catch (e) {
      turnError(handle, errText(e));
      finishThinking(handle, 'failed \u00B7 ' +
        fmtSeconds(Date.now() - handle.startedAt), 'error');
    } finally {
      stopTicker(handle);
      state.live = null;
      setStreaming(false);
      scrollToBottom(false);
      refreshSessions();
      refreshFleet();
      if (el.input) el.input.focus();
    }
  }

  /* ==========================================================================
     COMPOSER
     ========================================================================== */

  function autoGrow() {
    if (!el.input) return;
    el.input.style.height = 'auto';
    var next = Math.min(el.input.scrollHeight, 200);
    el.input.style.height = next + 'px';
    el.input.style.overflowY = (el.input.scrollHeight > 200) ? 'auto' : 'hidden';
    if (el.sendBtn && !state.streaming) {
      el.sendBtn.disabled = !el.input.value.trim();
    }
  }

  function submitFromComposer() {
    if (!el.input) return;
    var text = el.input.value;
    if (!text.trim()) return;
    send(text);
  }

  /* ==========================================================================
     NAV (narrow layout)
     ========================================================================== */

  function openNav() { document.body.classList.add('nav-open'); if (el.scrim) el.scrim.hidden = false; }
  function closeNav() { document.body.classList.remove('nav-open'); if (el.scrim) el.scrim.hidden = true; }
  function toggleNav() {
    if (document.body.classList.contains('nav-open')) closeNav(); else openNav();
  }

  /* ==========================================================================
     CLIPBOARD (code copy) - offline, no permissions prompt path first
     ========================================================================== */

  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* fall through to the legacy path */ }
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return !!ok;
    } catch (e2) {
      return false;
    }
  }

  /* ==========================================================================
     WIRING
     ========================================================================== */

  function bridgeCall(name) {
    try {
      if (bridge && typeof bridge[name] === 'function') { bridge[name](); return; }
      toast('Window control unavailable: ' + name);
    } catch (e) {
      toast('Window control failed: ' + errText(e));
    }
  }

  function bind() {
    if (el.winMin) el.winMin.addEventListener('click', function () { bridgeCall('minimize'); });
    if (el.winMax) el.winMax.addEventListener('click', function () { bridgeCall('maximize'); });
    if (el.winClose) el.winClose.addEventListener('click', function () { bridgeCall('close'); });

    if (el.navToggle) el.navToggle.addEventListener('click', toggleNav);
    if (el.scrim) el.scrim.addEventListener('click', closeNav);

    if (el.newChat) el.newChat.addEventListener('click', newChat);
    if (el.bannerRetry) el.bannerRetry.addEventListener('click', async function () {
      if (!bridge || typeof bridge.restartSidecar !== 'function') {
        toast('Backend restart unavailable');
        return;
      }
      el.bannerRetry.disabled = true;
      try {
        var result = await bridge.restartSidecar();
        if (!result || !result.ok) throw new Error(String((result && result.error) || 'restart failed'));
        hideBanner();
        await Promise.all([refreshHealth(), refreshFleet(), refreshSessions()]);
        toast('Backend restarted');
      } catch (err) {
        showBanner('Backend restart failed: ' + errText(err));
      } finally {
        el.bannerRetry.disabled = false;
      }
    });

    if (el.laneChip) el.laneChip.addEventListener('click', function (ev) {
      ev.stopPropagation();
      toggleLanePop();
    });
    if (el.settingsBtn) {
      el.settingsBtn.addEventListener('click', function (ev) { ev.stopPropagation(); openSettings(); });
    }
    if (el.settingsClose) {
      el.settingsClose.addEventListener('click', function (ev) { ev.stopPropagation(); closeSettings(); });
    }
    if (el.settingsScrim) {
      el.settingsScrim.addEventListener('click', function () { closeSettings(); });
    }
    if (el.settings) {
      el.settings.addEventListener('click', function (ev) { ev.stopPropagation(); });
    }

    if (el.laneFoot) el.laneFoot.addEventListener('click', function (ev) {
      ev.stopPropagation();
      openLanePop();
    });
    if (el.lanePop) el.lanePop.addEventListener('click', function (ev) { ev.stopPropagation(); });

    if (el.orchestrationToggle) el.orchestrationToggle.addEventListener('change', function () {
      // One ready execution lane is now enough: rows may repeat, so a single signed-in
      // model can still be an orchestrator plus as many workers as the owner wants.
      var candidates = orchestrationCandidates();
      if (el.orchestrationToggle.checked && !candidates.length) {
        el.orchestrationToggle.checked = false;
        state.orchestration.enabled = false;
        toast('No execution model is ready. Sign in to a lane or add an API key.');
      } else {
        state.orchestration.enabled = el.orchestrationToggle.checked;
      }
      sanitizeOrchestration();
      renderOrchestration();
      paintLane();
    });

    if (el.workerAdd) {
      el.workerAdd.addEventListener('click', function (ev) {
        ev.stopPropagation();
        addRoleRow('worker');
      });
    }
    if (el.advisorAdd) {
      el.advisorAdd.addEventListener('click', function (ev) {
        ev.stopPropagation();
        addRoleRow('validator');
      });
    }

    if (el.workspacePick) {
      el.workspacePick.addEventListener('click', function (ev) { ev.stopPropagation(); pickWorkspace(); });
    }
    if (el.workspaceReset) {
      el.workspaceReset.addEventListener('click', function (ev) {
        ev.stopPropagation();
        applyWorkspace('');
      });
    }

    if (el.apiAdd) el.apiAdd.addEventListener('click', function (ev) { ev.stopPropagation(); openApiForm(); });
    if (el.apiCancel) el.apiCancel.addEventListener('click', function (ev) { ev.stopPropagation(); closeApiForm(); });
    if (el.apiTest) el.apiTest.addEventListener('click', function (ev) { ev.stopPropagation(); testApiKey(); });
    if (el.apiSave) el.apiSave.addEventListener('click', function (ev) { ev.stopPropagation(); saveApiKey(); });
    if (el.apiProvider) el.apiProvider.addEventListener('change', syncApiFormProvider);
    if (el.apiForm) {
      el.apiForm.addEventListener('submit', function (ev) { ev.preventDefault(); saveApiKey(); });
    }

    document.addEventListener('click', function () { closeLanePop(); });

    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') {
        closeSettings();
        closeLanePop();
        closeNav();
      }
      if ((ev.ctrlKey || ev.metaKey) && (ev.key === 'n' || ev.key === 'N')) {
        ev.preventDefault();
        newChat();
      }
    });

    if (el.sendBtn) el.sendBtn.addEventListener('click', submitFromComposer);
    if (el.input) {
      el.input.addEventListener('input', autoGrow);
      el.input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && !ev.shiftKey && !ev.ctrlKey && !ev.altKey && !ev.metaKey) {
          if (ev.isComposing) return;
          ev.preventDefault();
          submitFromComposer();
        }
      });
    }

    var examples = document.querySelectorAll('.example');
    for (var i = 0; i < examples.length; i += 1) {
      examples[i].addEventListener('click', function (ev) {
        var node = ev.currentTarget;
        var prompt = node.getAttribute('data-prompt') || node.textContent;
        if (el.input) { el.input.value = prompt; autoGrow(); }
        send(prompt);
      });
    }

    if (el.turns) {
      el.turns.addEventListener('click', function (ev) {
        var btn = ev.target && ev.target.closest ? ev.target.closest('.copy-btn') : null;
        if (!btn) return;
        var block = btn.closest('.code-block');
        var code = block ? block.querySelector('.code-body code') : null;
        if (!code) return;
        copyText(code.textContent).then(function (ok) {
          btn.textContent = ok ? 'Copied' : 'Copy failed';
          btn.classList.toggle('is-done', !!ok);
          setTimeout(function () {
            btn.textContent = 'Copy';
            btn.classList.remove('is-done');
          }, 1400);
        });
      });
    }

    window.addEventListener('resize', function () {
      if (window.innerWidth > 900) closeNav();
    });
  }

  function init() {
    loadOrchestration();
    loadDisabledModels();
    bind();
    if (bridge && typeof bridge.onSidecarDown === 'function') {
      bridge.onSidecarDown(function (payload) {
        var reason = payload && payload.reason === 'turn_timeout'
          ? 'The answer exceeded the hard time limit.'
          : 'The backend exited unexpectedly.';
        showBanner(reason + ' Use Retry to start a fresh contained backend.');
        setStreaming(false);
      });
    }
    paintLane();
    autoGrow();
    setStreaming(false);
    renderBuildIdentity();
    renderSupportCard();
    if (el.supportClose) el.supportClose.addEventListener('click', dismissSupportCard);
    refreshHealth();
    refreshFleet();
    refreshSessions();
    renderOrchestration();
    if (el.input) el.input.focus();
    setInterval(refreshFleet, 45000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
