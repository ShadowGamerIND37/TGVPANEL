/* ==========================================================================
   HKVM PANEL — PREMIUM UX ENGINE
   Command palette, toasts, theme/accent/density studio, keyboard shortcuts,
   live status widgets, charts and quality-of-life helpers.
   Exposes window.PM.
   ========================================================================== */
(function () {
  'use strict';

  var PM = (window.PM = window.PM || {});
  var doc = document;

  /* ------------------------------------------------------------------ utils */
  function $(sel, root) { return (root || doc).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); }
  function el(tag, cls, html) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html;
    return n;
  }
  function store(key, value) {
    try {
      if (value === undefined) return window.localStorage.getItem('pm.' + key);
      if (value === null) return window.localStorage.removeItem('pm.' + key);
      window.localStorage.setItem('pm.' + key, value);
    } catch (e) { return null; }
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function clamp(n, min, max) { return Math.min(max, Math.max(min, n)); }
  function isMac() { return /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent); }
  function cmdKey() { return isMac() ? '⌘' : 'Ctrl'; }

  PM.esc = esc;
  PM.clamp = clamp;

  PM.formatBytes = function (bytes, digits) {
    if (!bytes && bytes !== 0) return '—';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0, n = Number(bytes);
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return n.toFixed(digits == null ? (n >= 100 || i === 0 ? 0 : 1) : digits) + ' ' + units[i];
  };

  PM.timeAgo = function (value) {
    if (!value) return '';
    var t = new Date(String(value).replace(' ', 'T') + (String(value).indexOf('Z') === -1 && String(value).indexOf('+') === -1 ? 'Z' : ''));
    if (isNaN(t.getTime())) t = new Date(value);
    var diff = Math.floor((Date.now() - t.getTime()) / 1000);
    if (diff < 5) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return t.toLocaleDateString();
  };

  PM.formatUptime = function (seconds) {
    seconds = Math.floor(Number(seconds) || 0);
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    if (d) return d + 'd ' + h + 'h';
    if (h) return h + 'h ' + m + 'm';
    return m + 'm';
  };

  PM.debounce = function (fn, wait) {
    var t;
    return function () {
      var ctx = this, args = arguments;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, wait || 200);
    };
  };

  PM.fetchJSON = function (url, opts) {
    return fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  };

  /* ------------------------------------------------------------------ icons */
  var ICONS = {
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    server: '<rect x="2" y="4" width="20" height="7" rx="2"/><rect x="2" y="13" width="20" height="7" rx="2"/><path d="M6 7.5h.01M6 16.5h.01"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6h.09A1.65 1.65 0 0 0 10 3.09V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
    moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
    sun: '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
    keyboard: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8"/>',
    bell: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    external: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    play: '<polygon points="6 4 20 12 6 20 6 4"/>',
    stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
    check: '<polyline points="20 6 9 17 4 12"/>',
    x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    alert: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    sparkles: '<path d="M12 3l1.9 4.6L18.5 9.5 13.9 11.4 12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><path d="M19 15l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    palette: '<circle cx="13.5" cy="6.5" r="1.5"/><circle cx="17.5" cy="10.5" r="1.5"/><circle cx="8.5" cy="7.5" r="1.5"/><circle cx="6.5" cy="12.5" r="1.5"/><path d="M12 2a10 10 0 1 0 0 20c1.1 0 2-.9 2-2 0-.5-.2-1-.5-1.3-.3-.4-.5-.8-.5-1.2 0-1.1.9-2 2-2h2.5c2.5 0 4.5-2 4.5-4.5C22 5.6 17.5 2 12 2z"/>'
  };

  PM.icon = function (name, size) {
    var s = size || 16;
    return '<svg width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' + (ICONS[name] || ICONS.info) + '</svg>';
  };

  /* ------------------------------------------------------------- appearance */
  var THEMES = ['dark', 'light'];
  var ACCENTS = {
    indigo: 'linear-gradient(135deg,#7c6cff,#a855f7)',
    violet: 'linear-gradient(135deg,#a855f7,#e879f9)',
    cyan: 'linear-gradient(135deg,#22d3ee,#3b82f6)',
    emerald: 'linear-gradient(135deg,#34d399,#0891b2)',
    rose: 'linear-gradient(135deg,#fb7185,#f97316)'
  };

  PM.getPrefs = function () {
    return {
      theme: store('theme') || 'dark',
      accent: store('accent') || 'indigo',
      density: store('density') || 'comfortable',
      motion: store('motion') !== 'off'
    };
  };

  PM.applyPrefs = function (prefs) {
    var p = prefs || PM.getPrefs();
    var body = doc.body;
    if (!body) return;

    if (p.theme === 'light') body.classList.add('light-theme');
    else body.classList.remove('light-theme');
    doc.documentElement.classList.toggle('pm-theme-light', p.theme === 'light');
    doc.documentElement.style.colorScheme = p.theme === 'light' ? 'light' : 'dark';
    if (p.accent && p.accent !== 'indigo') doc.documentElement.setAttribute('data-pm-accent', p.accent);
    else doc.documentElement.removeAttribute('data-pm-accent');

    if (p.accent && p.accent !== 'indigo') body.setAttribute('data-accent', p.accent);
    else body.removeAttribute('data-accent');

    body.classList.toggle('pm-compact', p.density === 'compact');
    body.classList.toggle('pm-reduce-motion', p.motion === false);

    var meta = $('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', p.theme === 'light' ? '#f4f5fb' : '#06070c');

    // keep legacy header buttons in sync
    var d = $('#darkThemeBtn'), l = $('#lightThemeBtn');
    if (d && l) {
      d.classList.toggle('active', p.theme !== 'light');
      l.classList.toggle('active', p.theme === 'light');
    }
    $$('.pm-swatch', doc).forEach(function (s) {
      s.classList.toggle('active', s.getAttribute('data-accent') === (p.accent || 'indigo'));
    });
    $$('[data-pm-density]').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-pm-density') === p.density);
    });
    var mBtn = $('#pmMotionToggle');
    if (mBtn) mBtn.checked = p.motion !== false;
  };

  PM.setTheme = function (theme) {
    store('theme', theme);
    var p = PM.getPrefs();
    p.theme = theme;
    PM.applyPrefs(p);
    PM.toast(theme === 'light' ? 'Light theme enabled' : 'Dark theme enabled', 'info', { icon: theme === 'light' ? 'sun' : 'moon', duration: 1800 });
  };
  PM.toggleTheme = function () {
    PM.setTheme(PM.getPrefs().theme === 'light' ? 'dark' : 'light');
  };
  PM.setAccent = function (accent) {
    store('accent', accent);
    var p = PM.getPrefs();
    p.accent = accent;
    PM.applyPrefs(p);
  };
  PM.setDensity = function (density) {
    store('density', density);
    var p = PM.getPrefs();
    p.density = density;
    PM.applyPrefs(p);
  };
  PM.setMotion = function (on) {
    store('motion', on ? 'on' : 'off');
    var p = PM.getPrefs();
    p.motion = on;
    PM.applyPrefs(p);
  };

  // Legacy compatibility (header partial + inline onclick handlers)
  window.setTheme = PM.setTheme;

  /* ----------------------------------------------------------------- toasts */
  function toastHost() {
    var host = $('.pm-toasts');
    if (!host) {
      host = el('div', 'pm-toasts');
      host.setAttribute('role', 'status');
      host.setAttribute('aria-live', 'polite');
      doc.body.appendChild(host);
    }
    return host;
  }

  /**
   * PM.toast('Saved', 'success', { title, icon, duration, action })
   */
  PM.toast = function (message, type, opts) {
    var o = opts || {};
    var kind = type || 'info';
    var host = toastHost();
    var node = el('div', 'pm-toast ' + kind);
    var icon = o.icon || (kind === 'success' ? 'check' : kind === 'error' ? 'x' : kind === 'warning' ? 'alert' : 'info');
    var duration = o.duration == null ? 4200 : o.duration;

    node.innerHTML =
      '<div class="pm-toast-icon">' + PM.icon(icon, 15) + '</div>' +
      '<div class="pm-toast-body">' +
        (o.title ? '<div class="pm-toast-title">' + esc(o.title) + '</div>' : '') +
        '<div class="pm-toast-msg">' + esc(message) + '</div>' +
      '</div>' +
      '<button class="pm-toast-close" aria-label="Dismiss">' + PM.icon('x', 13) + '</button>' +
      (duration ? '<div class="pm-toast-progress" style="animation-duration:' + duration + 'ms"></div>' : '');

    host.appendChild(node);

    var timer;
    function dismiss() {
      clearTimeout(timer);
      node.classList.add('out');
      setTimeout(function () { node.remove(); }, 240);
    }
    node.querySelector('.pm-toast-close').addEventListener('click', dismiss);
    if (duration) timer = setTimeout(dismiss, duration);

    // hover pauses dismissal
    node.addEventListener('mouseenter', function () { clearTimeout(timer); });
    node.addEventListener('mouseleave', function () {
      if (duration) timer = setTimeout(dismiss, 1400);
    });
    return node;
  };

  PM.success = function (m, t) { return PM.toast(m, 'success', { title: t }); };
  PM.error = function (m, t) { return PM.toast(m, 'error', { title: t, duration: 6000 }); };
  PM.info = function (m, t) { return PM.toast(m, 'info', { title: t }); };
  PM.warn = function (m, t) { return PM.toast(m, 'warning', { title: t }); };

  // Aliases for legacy scripts that call showToast()
  window.premiumToast = PM.toast;
  if (typeof window.showToast !== 'function') window.showToast = PM.toast;

  /* ---------------------------------------------------------------- confirm */
  PM.confirm = function (message, opts) {
    var o = opts || {};
    return new Promise(function (resolve) {
      var overlay = el('div', 'pm-sheet open');
      overlay.style.zIndex = '4400';
      var box = el('div', 'pm-sheet-box');
      box.style.width = 'min(460px, 100%)';
      box.innerHTML =
        '<div class="pm-sheet-head">' +
          '<div class="pm-row" style="gap:11px">' +
            '<span class="pm-feed-icon" style="width:34px;height:34px;color:var(--pm-amber);background:var(--pm-amber-soft);border-color:rgba(251,191,36,.3)">' + PM.icon('alert', 17) + '</span>' +
            '<div><div class="pm-sheet-title">' + esc(o.title || 'Please confirm') + '</div>' +
            '<div class="pm-muted" style="font-size:11px">This action needs your approval</div></div>' +
          '</div>' +
          '<button class="modal-close" data-pm-cancel aria-label="Close">' + PM.icon('x', 14) + '</button>' +
        '</div>' +
        '<div class="pm-sheet-body"><p style="margin:0;font-size:13px;color:var(--pm-text-soft);line-height:1.6">' + esc(message) + '</p></div>' +
        '<div class="pm-card-foot pm-row" style="justify-content:flex-end;gap:9px;padding:14px 18px">' +
          '<button class="btn btn-ghost" data-pm-cancel>Cancel</button>' +
          '<button class="btn ' + (o.danger === false ? 'btn-primary' : 'btn-danger') + '" data-pm-ok>' + esc(o.confirmText || 'Confirm') + '</button>' +
        '</div>';
      overlay.appendChild(box);
      doc.body.appendChild(overlay);

      function finish(val) {
        overlay.remove();
        doc.removeEventListener('keydown', onKey);
        resolve(val);
      }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); finish(false); }
        if (e.key === 'Enter') { e.preventDefault(); finish(true); }
      }
      doc.addEventListener('keydown', onKey);
      $$('[data-pm-cancel]', overlay).forEach(function (b) { b.addEventListener('click', function () { finish(false); }); });
      $('[data-pm-ok]', overlay).addEventListener('click', function () { finish(true); });
      overlay.addEventListener('click', function (e) { if (e.target === overlay) finish(false); });
      setTimeout(function () { var ok = $('[data-pm-ok]', overlay); if (ok) ok.focus(); }, 30);
    });
  };

  /* ------------------------------------------------------------------- copy */
  PM.copy = function (text, label) {
    function done() { PM.toast((label || 'Copied') + ' to clipboard', 'success', { duration: 2000 }); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else fallback();
    function fallback() {
      var ta = el('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
      doc.body.appendChild(ta);
      ta.select();
      try { doc.execCommand('copy'); done(); } catch (e) { PM.error('Copy failed'); }
      ta.remove();
    }
    return text;
  };

  /* -------------------------------------------------------------- progress */
  var progressEl;
  var progressTimer;
  PM.progress = {
    start: function () {
      if (!progressEl) {
        progressEl = el('div', 'pm-progress');
        doc.body.appendChild(progressEl);
      }
      clearInterval(progressTimer);
      var x = 0;
      progressEl.style.opacity = '1';
      progressEl.style.transform = 'scaleX(0.08)';
      progressTimer = setInterval(function () {
        x = Math.min(0.9, x + (0.9 - x) * 0.14);
        progressEl.style.transform = 'scaleX(' + x + ')';
      }, 220);
    },
    done: function () {
      if (!progressEl) return;
      clearInterval(progressTimer);
      progressEl.style.transform = 'scaleX(1)';
      setTimeout(function () {
        progressEl.style.opacity = '0';
        setTimeout(function () { progressEl.style.transform = 'scaleX(0)'; }, 260);
      }, 180);
    }
  };
  PM.startLoading = PM.progress.start;
  PM.stopLoading = PM.progress.done;

  /* ----------------------------------------------------------------- charts */
  PM.sparkline = function (target, data, opts) {
    var node = typeof target === 'string' ? $(target) : target;
    if (!node || !data || !data.length) return;
    var o = opts || {};
    var w = node.clientWidth || o.width || 220;
    var h = o.height || 38;
    var pad = 3;
    var max = Math.max.apply(null, data);
    var min = Math.min.apply(null, data);
    if (max === min) max = min + 1;
    var stepX = (w - pad * 2) / Math.max(1, data.length - 1);
    var pts = data.map(function (v, i) {
      var x = pad + i * stepX;
      var y = h - pad - ((v - min) / (max - min)) * (h - pad * 2);
      return [x, y];
    });
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join(' ');
    var area = line + ' L' + pts[pts.length - 1][0].toFixed(1) + ' ' + h + ' L' + pts[0][0].toFixed(1) + ' ' + h + ' Z';
    var id = 'pm-spark-' + Math.random().toString(36).slice(2, 8);
    var color = o.color || 'var(--pm-brand-2)';
    node.innerHTML =
      '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" style="width:100%;height:' + h + 'px;display:block">' +
        '<defs><linearGradient id="' + id + '" x1="0" y1="0" x2="0" y2="1">' +
          '<stop offset="0%" stop-color="' + color + '" stop-opacity="0.32"/>' +
          '<stop offset="100%" stop-color="' + color + '" stop-opacity="0"/>' +
        '</linearGradient></defs>' +
        '<path d="' + area + '" fill="url(#' + id + ')"/>' +
        '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>' +
      '</svg>';
  };

  PM.ring = function (target, percent, opts) {
    var node = typeof target === 'string' ? $(target) : target;
    if (!node) return;
    var o = opts || {};
    var p = clamp(Number(percent) || 0, 0, 100);
    var size = o.size || 62;
    var stroke = o.stroke || 6;
    var r = (size - stroke) / 2;
    var c = 2 * Math.PI * r;
    node.classList.add('pm-ring');
    node.style.setProperty('--pm-ring-size', size + 'px');
    if (!node.querySelector('svg')) {
      node.innerHTML =
        '<svg viewBox="0 0 ' + size + ' ' + size + '">' +
          '<defs><linearGradient id="pm-ring-grad" x1="0" y1="0" x2="1" y2="1">' +
            '<stop offset="0%" stop-color="#7c6cff"/><stop offset="100%" stop-color="#a855f7"/>' +
          '</linearGradient></defs>' +
          '<circle class="bg" cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '"/>' +
          '<circle class="val" cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '"/>' +
        '</svg>' +
        '<div class="pm-ring-label">0%</div>';
    }
    var val = node.querySelector('.val');
    var label = node.querySelector('.pm-ring-label');
    requestAnimationFrame(function () {
      val.setAttribute('stroke-dashoffset', String(c - (p / 100) * c));
      if (label) label.textContent = Math.round(p) + '%';
    });
  };

  PM.countUp = function (node, to, opts) {
    if (typeof node === 'string') node = $(node);
    if (!node) return;
    var o = opts || {};
    var from = Number(o.from || 0);
    var duration = o.duration || 700;
    var suffix = o.suffix || '';
    var start = performance.now();
    function step(now) {
      var t = clamp((now - start) / duration, 0, 1);
      var eased = 1 - Math.pow(1 - t, 3);
      node.textContent = Math.round(from + (to - from) * eased).toLocaleString() + suffix;
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  };

  /* ------------------------------------------------------- command palette */
  var palette = null;
  var paletteItems = [];
  var paletteIndex = 0;
  var paletteQuery = '';
  var cache = { vms: null, vmsAt: 0, users: null, usersAt: 0 };

  function isAdmin() {
    var b = doc.body;
    return b.getAttribute('data-role') === 'admin' || !!$('a[href="/admin/dashboard"]');
  }

  function runVMAction(action, vm) {
    PM.toast((action === 'start' ? 'Starting ' : 'Stopping ') + vm.vm_name + '…', 'info', { duration: 1800 });
    return fetch('/api/vms/' + vm.vm_id + '/' + action, { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (d) {
          if (!r.ok || d.success === false) throw new Error(d.error || 'Request failed');
          PM.success(vm.vm_name + (action === 'start' ? ' is booting' : ' is shutting down'));
          cache.vmsAt = 0;
          if (palette && palette.classList.contains('open')) {
            setTimeout(function () { ensureDynamic().then(function () { renderPalette(paletteQuery); }); }, 900);
          }
        });
      })
      .catch(function (e) { PM.error(e.message || 'Action failed'); });
  }

  function staticCommands() {
    var admin = isAdmin();
    var cmds = [
      { group: 'Navigation', title: 'Dashboard', sub: 'Overview & activity', icon: 'dashboard', href: admin ? '/admin/dashboard' : '/dashboard', keywords: 'home overview start' },
      { group: 'Navigation', title: 'Virtual Machines', sub: 'Browse and manage VMs', icon: 'server', href: admin ? '/admin/vms' : '/vms', keywords: 'vms instances servers machines' },
      { group: 'Navigation', title: 'My Profile', sub: 'Account & security', icon: 'users', href: '/profile', keywords: 'account user settings password' }
    ];
    if (admin) {
      cmds.push(
        { group: 'Navigation', title: 'User Panel', sub: 'Switch to end-user view', icon: 'home', href: '/dashboard', keywords: 'user view front' },
        { group: 'Navigation', title: 'Users', sub: 'Manage panel accounts', icon: 'users', href: '/admin/users', keywords: 'members accounts people' },
        { group: 'Create', title: 'Create Virtual Machine', sub: 'Provision a new VM', icon: 'plus', href: '/admin/vm-create', keywords: 'new vm provision deploy' },
        { group: 'Navigation', title: 'OS Templates', sub: 'Images & downloads', icon: 'server', href: '/admin/templates', keywords: 'images iso os downloads' },
        { group: 'Navigation', title: 'Settings', sub: 'Panel configuration', icon: 'settings', href: '/admin/settings', keywords: 'config preferences branding discord' }
      );
    }
    cmds.push({ group: 'Create', title: 'Open Settings Studio', sub: 'Theme, accent, density', icon: 'palette', action: openStudio, keywords: 'theme dark light accent color density appearance' });
    cmds.push({ group: 'Help', title: 'Keyboard Shortcuts', sub: 'All available hotkeys', icon: 'keyboard', action: openShortcuts, keywords: 'keys hotkeys help' });
    cmds.push({ group: 'Help', title: 'Toggle Theme', sub: 'Dark / light mode', icon: 'moon', action: PM.toggleTheme, keywords: 'dark light night mode' });
    cmds.push({ group: 'Help', title: 'Refresh Data', sub: 'Reload the page', icon: 'refresh', action: function () { location.reload(); }, keywords: 'reload sync' });
    return cmds;
  }

  function ensureDynamic() {
    var admin = isAdmin();
    var now = Date.now();
    var jobs = [];
    if (!cache.vms || now - cache.vmsAt > 30000) {
      jobs.push(PM.fetchJSON(admin ? '/api/admin/vms' : '/api/vms').then(function (vms) {
        cache.vms = (vms || []).slice(0, 40);
        cache.vmsAt = Date.now();
      }).catch(function () { cache.vms = cache.vms || []; }));
    }
    if (admin && (!cache.users || now - cache.usersAt > 60000)) {
      jobs.push(PM.fetchJSON('/api/admin/users').then(function (users) {
        cache.users = (users || []).slice(0, 40);
        cache.usersAt = Date.now();
      }).catch(function () { cache.users = cache.users || []; }));
    }
    return Promise.all(jobs);
  }

  var RECENT_KEY = 'pm.recent';

  function getRecent() {
    try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]').slice(0, 6); }
    catch (e) { return []; }
  }

  function rememberVisit(title, href) {
    try {
      var list = getRecent().filter(function (r) { return r.href !== href; });
      list.unshift({ title: (title || href).replace(/\s+/g, ' ').trim().slice(0, 48), href: href });
      localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 6)));
    } catch (e) { /* storage disabled */ }
  }

  function buildItems(q) {
    var query = (q || '').trim().toLowerCase();
    var admin = isAdmin();
    var items = [];

    function push(item) {
      if (!query) return items.push(item);
      var hay = (item.title + ' ' + (item.sub || '') + ' ' + (item.keywords || '')).toLowerCase();
      if (hay.indexOf(query) !== -1) {
        item.score = hay.indexOf(query) === 0 ? 0 : hay.indexOf(query);
        items.push(item);
      }
    }

    if (!query) {
      getRecent().forEach(function (r) {
        items.push({ group: 'Recent', title: r.title, sub: r.href, icon: 'external', href: r.href, keywords: 'recent last visited' });
      });
    }

    staticCommands().forEach(push);

    (cache.vms || []).forEach(function (vm) {
      push({
        group: 'Virtual Machines',
        title: vm.vm_name,
        sub: 'VM #' + vm.vm_id + ' · ' + (vm.status || 'unknown') + (vm.ipv4_address ? ' · ' + vm.ipv4_address : ''),
        icon: 'server',
        href: (admin ? '/admin/vm/' : '/vm/') + vm.vm_id,
        keywords: vm.template_name + ' ' + vm.os_type + ' ' + vm.ipv4_address + ' ' + vm.owner_username + ' ' + vm.status
      });
      var live = (vm.status || '').toLowerCase() === 'running';
      var nextAction = live ? 'stop' : 'start';
      push({
        group: 'Actions',
        title: (live ? 'Stop · ' : 'Start · ') + vm.vm_name,
        sub: live ? 'Graceful shutdown' : 'Boot this machine',
        icon: live ? 'stop' : 'play',
        action: (function (v, a) { return function () { runVMAction(a, v); }; })(vm, nextAction),
        keywords: (live ? 'stop shutdown power off ' : 'start boot power on launch ') + vm.vm_name
      });
      push({
        group: 'Virtual Machines',
        title: 'Console · ' + vm.vm_name,
        sub: 'Open VNC console',
        icon: 'terminal',
        href: (admin ? '/admin/vm/' : '/vm/') + vm.vm_id + '/console',
        keywords: 'console vnc screen ' + vm.vm_name
      });
    });

    if (admin) {
      (cache.users || []).forEach(function (u) {
        push({
          group: 'Users',
          title: u.username,
          sub: (u.email || u.role || 'user') + ' · #' + u.id,
          icon: 'users',
          href: '/admin/users/' + u.id + '/edit',
          keywords: 'user member account ' + u.email + ' ' + u.role
        });
      });
    }

    if (!query) {
      var seen = {};
      items = items.filter(function (it) {
        var key = it.href || ('t:' + it.title);
        if (seen[key]) return false;
        seen[key] = 1;
        return true;
      });
    }

    if (query && items.length) items.sort(function (a, b) { return (a.score || 0) - (b.score || 0); });
    return items;
  }

  function renderPalette(q) {
    paletteQuery = q;
    paletteItems = buildItems(q);
    paletteIndex = 0;
    var body = $('.pm-palette-body', palette);
    if (!body) return;
    if (!paletteItems.length) {
      body.innerHTML = '<div class="pm-palette-empty">' + PM.icon('search', 22) + '<div style="margin-top:10px">No results for “' + esc(q) + '”</div>' +
        '<div style="margin-top:4px;font-size:11px">Try a VM name, user, page or action.</div></div>';
      return;
    }
    var out = '';
    var lastGroup = null;
    paletteItems.forEach(function (item, i) {
      if (item.group !== lastGroup) {
        out += '<div class="pm-palette-group-label">' + esc(item.group) + '</div>';
        lastGroup = item.group;
      }
      out += '<div class="pm-palette-item' + (i === 0 ? ' active' : '') + '" data-index="' + i + '">' +
        '<span class="pm-pi-icon">' + PM.icon(item.icon || 'info', 14) + '</span>' +
        '<span class="pm-pi-main"><span class="pm-pi-title">' + esc(item.title) + '</span>' +
        '<span class="pm-pi-sub">' + esc(item.sub || '') + '</span></span>' +
        '<span class="pm-pi-hint">↵</span>' +
      '</div>';
    });
    body.innerHTML = out;

    $$('.pm-palette-item', body).forEach(function (node) {
      node.addEventListener('mouseenter', function () { setActive(Number(node.getAttribute('data-index'))); });
      node.addEventListener('click', function () { runItem(Number(node.getAttribute('data-index'))); });
    });
  }

  function setActive(i) {
    if (!paletteItems.length) return;
    paletteIndex = (i + paletteItems.length) % paletteItems.length;
    $$('.pm-palette-item', palette).forEach(function (n) {
      n.classList.toggle('active', Number(n.getAttribute('data-index')) === paletteIndex);
    });
    var active = $('.pm-palette-item.active', palette);
    if (active) active.scrollIntoView({ block: 'nearest' });
  }

  function runItem(i) {
    var item = paletteItems[i];
    if (!item) return;
    closePalette();
    if (item.action) return item.action();
    if (item.href) {
      PM.progress.start();
      location.href = item.href;
    }
  }

  function buildPalette() {
    palette = el('div', 'pm-palette');
    palette.setAttribute('role', 'dialog');
    palette.setAttribute('aria-modal', 'true');
    palette.setAttribute('aria-label', 'Command palette');
    palette.innerHTML =
      '<div class="pm-palette-box">' +
        '<div class="pm-palette-head">' +
          PM.icon('search', 18) +
          '<input class="pm-palette-input" type="text" placeholder="Search VMs, users, pages or run a command…" autocomplete="off" spellcheck="false">' +
          '<span class="pm-kbd">ESC</span>' +
        '</div>' +
        '<div class="pm-palette-body"></div>' +
        '<div class="pm-palette-foot">' +
          '<span><span class="pm-kbd">↑</span><span class="pm-kbd">↓</span> navigate</span>' +
          '<span><span class="pm-kbd">↵</span> open</span>' +
          '<span class="pm-right"><span class="pm-kbd">' + cmdKey() + '</span><span class="pm-kbd">K</span></span>' +
        '</div>' +
      '</div>';

    palette.addEventListener('click', function (e) { if (e.target === palette) closePalette(); });
    doc.body.appendChild(palette);

    var input = $('.pm-palette-input', palette);
    input.addEventListener('input', function () { renderPalette(this.value); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive(paletteIndex + 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(paletteIndex - 1); }
      else if (e.key === 'Enter') { e.preventDefault(); runItem(paletteIndex); }
      else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
    });
  }

  PM.openPalette = function (initialQuery) {
    if (!palette) buildPalette();
    palette.classList.add('open');
    doc.body.classList.add('pm-palette-open');
    var input = $('.pm-palette-input', palette);
    input.value = initialQuery || '';
    renderPalette(input.value);
    setTimeout(function () { input.focus(); input.select(); }, 20);
    ensureDynamic().then(function () { if (palette.classList.contains('open')) renderPalette(input.value); });
    PM.progress.start();
    setTimeout(PM.progress.done, 420);
  };
  function closePalette() {
    if (!palette) return;
    palette.classList.remove('open');
    doc.body.classList.remove('pm-palette-open');
  }
  PM.closePalette = closePalette;

  /* --------------------------------------------------------------- shortcuts */
  function openShortcuts() {
    var sheet = $('.pm-sheet.pm-shortcuts');
    if (!sheet) {
      sheet = el('div', 'pm-sheet pm-shortcuts');
      sheet.innerHTML =
        '<div class="pm-sheet-box">' +
          '<div class="pm-sheet-head">' +
            '<div><div class="pm-sheet-title">Keyboard shortcuts</div><div class="pm-muted" style="font-size:11px">Work at the speed of thought</div></div>' +
            '<button class="modal-close" data-close>' + PM.icon('x', 14) + '</button>' +
          '</div>' +
          '<div class="pm-sheet-body">' +
            '<div class="pm-subhead">General</div>' +
            shortcutRow('Command palette', [cmdKey(), 'K']) +
            shortcutRow('Quick search', ['/']) +
            shortcutRow('Toggle theme', ['T']) +
            shortcutRow('Shortcut help', ['?']) +
            shortcutRow('Close dialog / palette', ['Esc']) +
            '<div class="pm-subhead">Navigation</div>' +
            shortcutRow('Go to dashboard', ['G', 'D']) +
            shortcutRow('Go to virtual machines', ['G', 'V']) +
            shortcutRow('Go to users', ['G', 'U']) +
            shortcutRow('Go to settings', ['G', 'S']) +
            shortcutRow('Create new VM', ['N']) +
            '<div class="pm-subhead">Lists</div>' +
            shortcutRow('Move between rows', ['↑', '↓']) +
            shortcutRow('Open focused item', ['↵']) +
            shortcutRow('Refresh data', ['R']) +
          '</div>' +
        '</div>';
      doc.body.appendChild(sheet);
      sheet.addEventListener('click', function (e) {
        if (e.target === sheet || e.target.closest('[data-close]')) sheet.classList.remove('open');
      });
    }
    sheet.classList.add('open');
  }
  function shortcutRow(label, keys) {
    return '<div class="pm-shortcut-row"><span>' + esc(label) + '</span><span class="pm-shortcut-keys">' +
      keys.map(function (k) { return '<kbd class="pm-kbd">' + esc(k) + '</kbd>'; }).join('') + '</span></div>';
  }
  PM.openShortcuts = openShortcuts;

  /* ------------------------------------------------------- settings studio */
  function openStudio() {
    var pop = $('#pmStudio');
    if (!pop) {
      pop = el('div', 'pm-popover');
      pop.id = 'pmStudio';
      pop.innerHTML =
        '<div class="pm-popover-label">Appearance</div>' +
        '<div class="pm-segmented" style="width:100%">' +
          '<button data-pm-theme="dark" style="flex:1">' + PM.icon('moon', 13) + ' Dark</button>' +
          '<button data-pm-theme="light" style="flex:1">' + PM.icon('sun', 13) + ' Light</button>' +
        '</div>' +
        '<div class="pm-popover-row"><span class="pm-popover-label-inline">Accent</span></div>' +
        '<div class="pm-swatches" style="margin-top:6px">' +
          Object.keys(ACCENTS).map(function (k) {
            return '<button class="pm-swatch" data-accent="' + k + '" title="' + k + '" style="background:' + ACCENTS[k] + '"></button>';
          }).join('') +
        '</div>' +
        '<div class="pm-popover-row"><span class="pm-popover-label-inline">Density</span>' +
          '<span class="pm-segmented">' +
            '<button data-pm-density="comfortable">Comfort</button>' +
            '<button data-pm-density="compact">Compact</button>' +
          '</span>' +
        '</div>' +
        '<div class="pm-popover-row"><span class="pm-popover-label-inline">Animations</span>' +
          '<label class="toggle-switch" style="margin:0"><input type="checkbox" class="toggle-input" id="pmMotionToggle"><span class="toggle-track"><span class="toggle-thumb"></span></span></label>' +
        '</div>' +
        '<div class="pm-popover-row" style="border-top:1px solid var(--pm-line-soft);padding-top:10px;margin-top:12px">' +
          '<button class="btn btn-ghost btn-sm" style="width:100%" data-pm-shortcuts>' + PM.icon('keyboard', 13) + ' Keyboard shortcuts</button>' +
        '</div>';
      doc.body.appendChild(pop);

      pop.addEventListener('click', function (e) {
        var themeBtn = e.target.closest('[data-pm-theme]');
        var accBtn = e.target.closest('[data-accent]');
        var denBtn = e.target.closest('[data-pm-density]');
        if (themeBtn) PM.setTheme(themeBtn.getAttribute('data-pm-theme'));
        if (accBtn) PM.setAccent(accBtn.getAttribute('data-accent'));
        if (denBtn) PM.setDensity(denBtn.getAttribute('data-pm-density'));
        if (e.target.closest('[data-pm-shortcuts]')) { pop.classList.remove('open'); openShortcuts(); }
        PM.applyPrefs();
      });
      pop.addEventListener('change', function (e) {
        if (e.target.id === 'pmMotionToggle') PM.setMotion(e.target.checked);
      });
    }

    var trigger = $('#pmStudioBtn') || $('#themeBtn');
    var rect = trigger ? trigger.getBoundingClientRect() : { right: window.innerWidth - 20, bottom: 70 };
    pop.style.top = Math.round(rect.bottom + 10) + 'px';
    pop.style.right = Math.max(12, Math.round(window.innerWidth - rect.right)) + 'px';
    pop.classList.toggle('open');
    PM.applyPrefs();
  }
  PM.openStudio = openStudio;

  doc.addEventListener('click', function (e) {
    var pop = $('#pmStudio');
    if (!pop || !pop.classList.contains('open')) return;
    if (e.target.closest('#pmStudio') || e.target.closest('#pmStudioBtn') || e.target.closest('#themeBtn')) return;
    pop.classList.remove('open');
  });

  /* ------------------------------------------------------- notifications */
  function initNotifications() {
    var list = $('#pmNotifList');
    var dot = $('#pmNotifDot') || $('#notifDot');
    if (!list) return;
    PM.fetchJSON('/api/activity?limit=12').then(function (rows) {
      var items = rows || [];
      var lastSeen = Number(store('notif.' + (doc.body.getAttribute('data-user') || 'me')) || 0);
      var newest = items.reduce(function (max, r) { return Math.max(max, Number(r.id) || 0); }, 0);
      if (dot && newest > lastSeen) dot.style.display = 'block';

      if (!items.length) {
        list.innerHTML = '<div style="padding:24px;text-align:center;color:var(--pm-text-dim);font-size:12px">' +
          '<div class="pm-empty-icon">' + PM.icon('bell', 20) + '</div>No activity yet</div>';
        return;
      }
      list.innerHTML = items.map(function (r) {
        var kind = (r.status === 'error' || r.action === 'delete') ? 'error' : (r.action === 'start' ? 'start' : (r.action === 'create' ? 'create' : 'stop'));
        return '<div class="pm-feed-item">' +
          '<span class="pm-feed-icon ' + kind + '">' + PM.icon(r.action === 'start' ? 'play' : r.action === 'stop' ? 'stop' : r.action === 'create' ? 'plus' : 'info', 13) + '</span>' +
          '<span class="pm-feed-body"><span class="pm-feed-title">' + esc(r.message || r.action) + '</span>' +
          '<span class="pm-feed-meta">' + esc(r.vm_name ? 'VM · ' + r.vm_name : 'Panel') + '</span></span>' +
          '<span class="pm-feed-time">' + esc(PM.timeAgo(r.timestamp)) + '</span>' +
        '</div>';
      }).join('');

      if (dot) {
        dot.style.display = 'block';
        store('notifSeen', String(newest));
      }
    }).catch(function () {});
  }

  PM.markNotificationsRead = function () {
    var dot = $('#pmNotifDot') || $('#notifDot');
    if (dot) dot.style.display = 'none';
  };

  /* --------------------------------------------------- sidebar / shell UX */
  function initSidebar() {
    var sidebar = $('#adminSidebar');
    if (!sidebar) return;

    $$('.nav-item', sidebar).forEach(function (item) {
      var label = item.querySelector('.nav-text');
      if (label) item.setAttribute('data-label', label.textContent.trim());
    });

    // restore rail state
    if (store('rail') === '1' && window.innerWidth > 1024) doc.body.classList.add('pm-rail');

    var railBtn = $('#pmRailBtn');
    if (railBtn) {
      railBtn.addEventListener('click', function () {
        doc.body.classList.toggle('pm-rail');
        store('rail', doc.body.classList.contains('pm-rail') ? '1' : '0');
      });
    }

    // nav filter
    var filter = $('#pmNavFilter');
    if (filter) {
      filter.addEventListener('input', function () {
        var q = this.value.toLowerCase();
        $$('.nav-item', sidebar).forEach(function (item) {
          var label = (item.getAttribute('data-label') || '').toLowerCase();
          var match = !q || label.indexOf(q) !== -1;
          item.style.display = match ? '' : 'none';
        });
        $$('.nav-section', sidebar).forEach(function (section) {
          var visible = $$('.nav-item', section).some(function (i) { return i.style.display !== 'none'; });
          section.style.display = visible ? '' : 'none';
        });
      });
      // shortcut to focus nav filter
      doc.addEventListener('keydown', function (e) {
        if (e.key === '/' && !isTyping(e)) { e.preventDefault(); filter.focus(); }
      });
    }

    // Ensure mobile drawer behaves
    window.toggleSidebar = function () {
      if (window.innerWidth > 1024) {
        doc.body.classList.toggle('pm-rail');
        store('rail', doc.body.classList.contains('pm-rail') ? '1' : '0');
        return;
      }
      sidebar.classList.toggle('open');
      var overlay = $('#sidebarOverlay');
      if (overlay) overlay.classList.toggle('open');
      doc.body.style.overflow = sidebar.classList.contains('open') ? 'hidden' : '';
    };
    window.closeSidebar = function () {
      sidebar.classList.remove('open');
      var overlay = $('#sidebarOverlay');
      if (overlay) overlay.classList.remove('open');
      doc.body.style.overflow = '';
    };
  }

  function initSidebarMeters() {
    var host = $('#pmSidebarUsage');
    if (!host) return;
    function paint(m) {
      if (!m) return;
      host.innerHTML =
        '<div class="sidebar-usage-head"><span>Host load</span><span>' + Math.round(m.cpu.percent) + '%</span></div>' +
        '<div class="sidebar-usage-bar"><span style="width:' + clamp(m.cpu.percent, 2, 100) + '%"></span></div>' +
        '<div class="sidebar-usage-row"><span>RAM</span><span>' + PM.formatBytes(m.memory.used) + ' / ' + PM.formatBytes(m.memory.total) + '</span></div>' +
        '<div class="sidebar-usage-bar" style="margin-top:5px"><span style="width:' + clamp(m.memory.percent, 2, 100) + '%;background:linear-gradient(90deg,#22d3ee,#3b82f6)"></span></div>';
    }
    PM.fetchJSON('/api/system/metrics').then(paint).catch(function () {});
    setInterval(function () { PM.fetchJSON('/api/system/metrics').then(paint).catch(function () {}); }, 25000);
  }

  /* ---------------------------------------------------------------- header */
  function initHeader() {
    var search = $('#globalSearch');
    if (search) {
      search.setAttribute('readonly', 'readonly');
      search.addEventListener('focus', function () { PM.openPalette(''); this.blur(); });
      search.addEventListener('click', function () { PM.openPalette(''); });
    }
    var trigger = $('#pmPaletteTrigger');
    if (trigger) trigger.addEventListener('click', function (e) { e.preventDefault(); PM.openPalette(''); });

    var studioBtn = $('#pmStudioBtn');
    if (studioBtn) studioBtn.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); openStudio(); });

    var notifBtn = $('#notifBtn');
    if (notifBtn) notifBtn.addEventListener('click', function () { PM.markNotificationsRead(); });

    // clock
    var clock = $('#pmClock');
    if (clock) {
      function tick() {
        clock.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
      tick();
      setInterval(tick, 15000);
    }

    var notifTrigger = $('#pmNotifTrigger');
    if (notifTrigger) notifTrigger.addEventListener('click', initNotifications);
  }

  /* ------------------------------------------------------ progressive polish */
  function initReveal() {
    var nodes = $$('.pm-card, .card, .stat-card, .stat-card-enhanced, .quick-action-card, .vm-card, .vm-card-enhanced, .pm-hero, .settings-section');
    if (!('IntersectionObserver' in window)) {
      nodes.forEach(function (n) { n.classList.add('pm-reveal', 'in'); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -30px 0px', threshold: 0.04 });

    nodes.forEach(function (node, i) {
      if (node.closest('.pm-palette, .pm-sheet, .pm-popover, .modal')) return;
      node.classList.add('pm-reveal');
      node.style.transitionDelay = Math.min(i * 24, 260) + 'ms';
      io.observe(node);
    });
  }

  function initTables() {
    $$('table.table').forEach(function (t) {
      if (!t.parentElement || !t.parentElement.classList.contains('table-container')) {
        var wrap = el('div', 'table-container');
        t.parentNode.insertBefore(wrap, t);
        wrap.appendChild(t);
      }
    });
  }

  function initCopyButtons() {
    doc.addEventListener('click', function (e) {
      var target = e.target.closest('[data-pm-copy]');
      if (!target) return;
      e.preventDefault();
      var value = target.getAttribute('data-pm-copy');
      if (!value) {
        var sel = target.getAttribute('data-pm-copy-target');
        if (sel) { var src = $(sel); value = src ? (src.value || src.textContent) : ''; }
      }
      if (value) PM.copy(value, target.getAttribute('data-pm-copy-label') || 'Copied');
    });
  }

  function initTooltips() {
    var tip;
    doc.addEventListener('mouseover', function (e) {
      var target = e.target.closest('[data-pm-tip]');
      if (!target) return;
      if (!tip) {
        tip = el('div', 'pm-popover');
        tip.style.cssText = 'padding:6px 9px;min-width:0;font-size:11px;color:var(--pm-text);pointer-events:none;';
        doc.body.appendChild(tip);
      }
      tip.textContent = target.getAttribute('data-pm-tip');
      tip.classList.add('open');
      var rect = target.getBoundingClientRect();
      tip.style.top = (rect.top - tip.offsetHeight - 8) + 'px';
      tip.style.left = clamp(rect.left + rect.width / 2 - tip.offsetWidth / 2, 8, window.innerWidth - tip.offsetWidth - 8) + 'px';
      tip.style.right = 'auto';
    });
    doc.addEventListener('mouseout', function (e) {
      if (tip && e.target.closest && e.target.closest('[data-pm-tip]')) tip.classList.remove('open');
    });
  }

  function initForms() {
    $$('form').forEach(function (form) {
      form.addEventListener('submit', function () {
        var btn = form.querySelector('button[type="submit"], .btn-primary');
        if (!btn || btn.disabled) return;
        if (btn.classList.contains('pm-no-loader')) return;
        var original = btn.innerHTML;
        btn.classList.add('loading');
        btn.style.pointerEvents = 'none';
        setTimeout(function () {
          btn.innerHTML = '<span class="pm-btn-spin"></span> Working…';
        }, 160);
        setTimeout(function () {
          btn.classList.remove('loading');
          btn.style.pointerEvents = '';
          btn.innerHTML = original;
        }, 12000);
      });
    });
  }

  function initFetchProgress() {
    if (!window.fetch || window.fetch.__pm) return;
    var nativeFetch = window.fetch.bind(window);
    var pending = 0;
    window.fetch = function () {
      pending++;
      if (pending === 1) PM.progress.start();
      return nativeFetch.apply(null, arguments).finally(function () {
        pending = Math.max(0, pending - 1);
        if (pending === 0) PM.progress.done();
      });
    };
    window.fetch.__pm = true;
  }

  function initOnlineState() {
    window.addEventListener('offline', function () { PM.warn('You are offline — changes may not save', 'Connection lost'); });
    window.addEventListener('online', function () { PM.success('Connection restored', 'Back online'); });
  }

  function initLinks() {
    doc.addEventListener('click', function (e) {
      var a = e.target.closest('a[href]');
      if (!a) return;
      var href = a.getAttribute('href');
      if (!href || href.charAt(0) === '#' || href.indexOf('javascript') === 0) return;
      if (a.target === '_blank' || a.hasAttribute('download')) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      if (href.indexOf(location.origin) === 0 || href.charAt(0) === '/') {
        PM.progress.start();
        if (href.indexOf('/api/') !== 0) {
          rememberVisit((a.textContent || '').trim() || href, href);
        }
      }
    });
    window.addEventListener('beforeunload', function () { PM.progress.start(); });
  }

  function isTyping(e) {
    var t = e.target;
    if (!t) return false;
    var tag = (t.tagName || '').toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || t.isContentEditable;
  }

  function initShortcuts() {
    var lastG = 0;
    doc.addEventListener('keydown', function (e) {
      // palette
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        if (palette && palette.classList.contains('open')) closePalette();
        else PM.openPalette('');
        return;
      }
      if (e.key === 'Escape') {
        closePalette();
        var studio = $('#pmStudio');
        if (studio) studio.classList.remove('open');
        var sheet = $('.pm-sheet.open');
        if (sheet && !sheet.classList.contains('pm-confirm')) sheet.classList.remove('open');
        return;
      }
      if (isTyping(e) || e.metaKey || e.ctrlKey || e.altKey) return;

      if (e.key === '?') { e.preventDefault(); openShortcuts(); return; }
      if (e.key === 't' || e.key === 'T') { PM.toggleTheme(); return; }
      if (e.key === '/') { e.preventDefault(); PM.openPalette(''); return; }

      if (e.key === 'g' || e.key === 'G') { lastG = Date.now(); return; }
      if (Date.now() - lastG < 900) {
        var map = { d: '/dashboard', v: '/vms', u: '/admin/users', s: '/admin/settings', t: '/admin/templates' };
        var target = map[e.key.toLowerCase()];
        if (target) {
          var admin = isAdmin();
          if (admin && target === '/dashboard') target = '/admin/dashboard';
          if (admin && target === '/vms') target = '/admin/vms';
          if (!admin && ['/admin/users', '/admin/settings', '/admin/templates'].indexOf(target) !== -1) return;
          e.preventDefault();
          location.href = target;
          return;
        }
      }
      if (e.key === 'n' || e.key === 'N') {
        if (isAdmin()) { location.href = '/admin/vm-create'; }
      }
    });
  }

  /* ------------------------------------------------------- legacy icon shim */
  /* A handful of older pages still use Font Awesome glyphs (<i class="fas fa-x">).
     When the CDN is unreachable (offline panels, locked-down networks) those
     icons silently disappear. Swap them for the bundled inline SVG set. */
  var FA = {
    'fa-eye': '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    'fa-eye-slash': '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-6.4 0-10-7-10-7a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c6.4 0 10 7 10 7a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="2" y1="2" x2="22" y2="22"/>',
    'fa-check-circle': '<circle cx="12" cy="12" r="9"/><polyline points="8.5 12.5 11 15 16 9.5"/>',
    'fa-check': '<polyline points="20 6 9 17 4 12"/>',
    'fa-info-circle': '<circle cx="12" cy="12" r="9"/><line x1="12" y1="16" x2="12" y2="11"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    'fa-times-circle': '<circle cx="12" cy="12" r="9"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    'fa-exclamation-triangle': '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    'fa-exclamation-circle': '<circle cx="12" cy="12" r="9"/><line x1="12" y1="7.5" x2="12" y2="13"/><line x1="12" y1="16.5" x2="12.01" y2="16.5"/>',
    'fa-crown': '<path d="M3 7l4 4 5-7 5 7 4-4-2 12H5L3 7z"/>',
    'fa-arrow-left': '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    'fa-save': '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    'fa-lock': '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    'fa-user': '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    'fa-users': '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    'fa-user-plus': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="16" y1="11" x2="22" y2="11"/>',
    'fa-user-edit': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 11l3 3-5 5h-3v-3z"/>',
    'fa-trash': '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
    'fa-edit': '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    'fa-terminal': '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    'fa-play': '<polygon points="6 4 20 12 6 20 6 4"/>',
    'fa-shield': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    'fa-search': '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    'fa-microchip': '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
    'fa-link': '<path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.4"/><path d="M14 11a5 5 0 0 0-7.07 0L4.1 13.83a5 5 0 0 0 7.07 7.07L12.5 19.6"/>',
    'fa-sliders-h': '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    'fa-sitemap': '<rect x="9" y="2" width="6" height="5" rx="1"/><rect x="2" y="17" width="6" height="5" rx="1"/><rect x="16" y="17" width="6" height="5" rx="1"/><path d="M12 7v5M5 17v-3h14v3"/>',
    'fa-server': '<rect x="2" y="4" width="20" height="7" rx="2"/><rect x="2" y="13" width="20" height="7" rx="2"/><path d="M6 7.5h.01M6 16.5h.01"/>',
    'fa-sync-alt': '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    'fa-redo': '<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>',
    'fa-network-wired': '<rect x="9" y="2" width="6" height="6" rx="1"/><path d="M12 8v4M5 20h14"/><rect x="2" y="14" width="6" height="6" rx="1"/><rect x="16" y="14" width="6" height="6" rx="1"/>',
    'fa-memory': '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 7v10M12 7v10M17 7v10"/>',
    'fa-list': '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    'fa-key': '<path d="M21 2l-2 2m-7.6 7.6a5 5 0 1 0-7.07 7.07 5 5 0 0 0 7.07-7.07zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/>',
    'fa-hdd': '<rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 13l2-9h8l2 9"/><line x1="6" y1="17" x2="6.01" y2="17"/><line x1="10" y1="17" x2="10.01" y2="17"/>',
    'fa-globe': '<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z"/>',
    'fa-ethernet': '<rect x="3" y="9" width="18" height="10" rx="2"/><path d="M7 9V5M12 9V4M17 9V5"/>',
    'fa-cog': '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6h.09A1.65 1.65 0 0 0 10 3.09V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    'fa-cogs': '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6h.09A1.65 1.65 0 0 0 10 3.09V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    'fa-bolt': '<polyline points="13 2 3 14 11 14 10 22 21 10 13 10 13 2"/>',
    'fa-plug': '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-6 6 6 6 0 0 1-6-6z"/><path d="M12 17v5"/>',
    'fa-times': '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    'fa-plus': '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>'
  };

  function initLegacyIcons() {
    var nodes = $$('i.fas, i.far, i.fal, i.fa, i.fa-solid');
    if (!nodes.length) return;
    nodes.forEach(function (node) {
      try {
        var before = window.getComputedStyle(node, '::before').content;
        if (before && before !== 'none' && before !== 'normal' && before !== '""') return; // FA really loaded
      } catch (e) { /* jsdom */ }
      var name = null;
      for (var i = 0; i < node.classList.length; i++) {
        if (FA[node.classList[i]]) { name = node.classList[i]; break; }
      }
      if (!name) return;
      node.innerHTML = '<svg width="1em" height="1em" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">' + FA[name] + '</svg>';
      node.classList.add('pm-icon-shim');
      node.setAttribute('aria-hidden', 'true');
    });
  }

  /* ------------------------------------------------------------------- boot */
  function init() {
    // role marker for palette + shortcuts
    var admin = !!$('a[href="/admin/users"]') || !!$('a[href="/admin/vm-create"]') || !!$('a[href="/admin/dashboard"]') || doc.body.getAttribute('data-role') === 'admin';
    doc.body.setAttribute('data-role', admin ? 'admin' : 'user');
    // Pages without a sidebar (console / ssh terminal) give no visual role hint — ask the API.
    if (!admin && typeof window.fetch === 'function' && !$('a[href^="/admin/"]') && !$('.pm-sidebar, .admin-sidebar, .user-sidebar')) {
      fetch('/api/auth/check', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (d && d.authenticated && d.user && d.user.role === 'admin') doc.body.setAttribute('data-role', 'admin');
        })
        .catch(function () {});
    }

    PM.applyPrefs();
    initFetchProgress();
    initSidebar();
    initSidebarMeters();
    initHeader();
    initTables();
    initCopyButtons();
    initTooltips();
    initLinks();
    initShortcuts();
    initOnlineState();
    initNotifications();
    setTimeout(initReveal, 60);
    initForms();
    initLegacyIcons();

    // second reveal pass for lazily rendered content
    setTimeout(initReveal, 1800);

    // expose current page for scripts
    doc.body.setAttribute('data-pm-ready', '1');
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
  else init();

  /* -------------------------------------------------- early paint helper */
  // Applied inline in <head> by partials/premium-head so first paint is correct.
  window.PM = PM;
})();
