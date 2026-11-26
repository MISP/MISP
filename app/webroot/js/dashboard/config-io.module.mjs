// Dashboard config import / export module.
//
// Opens the configure side panel in one of two new modes — "export"
// and "import" — reusing the panel chrome the same way gallery.module
// .mjs does (backdrop, ✕, Cancel, ESC, the `hidden`-attribute close
// signal). This keeps the feature theme-independent: it depends only
// on the dashboard's own shared markup + CSS, NOT on either theme's
// global modal (the default theme's jQuery `openGenericModal` and
// Overmind's `openModal` are mutually incompatible and neither is
// present on both themes — see DD-08 / the dashboard layouts).
//
//   Export — fetches the saved dashboard config from /dashboards/export
//   (REST), unwraps it to the bare widget array, and shows it pretty-
//   printed in a read-only textarea with a Copy button.
//
//   Import — offers a textarea; on Load it parses + normalises the
//   pasted blob to a widget array (tolerating the v1 export envelopes)
//   and POSTs it to /dashboards/updateSettings — the board's own save
//   endpoint, which applies LayoutFixup and is CSRF-exempt for the
//   Accept: application/json path — then reloads so the board re-paints
//   from the imported config. This sidesteps the legacy /dashboards/
//   import action's envelope-unwrap quirk and round-trips cleanly with
//   what Export produces.
//
// Coupling with configure.module.mjs mirrors gallery.module.mjs: the
// shared ✕ / Cancel / backdrop close chain flips the panel's `hidden`
// attribute; a MutationObserver on it runs our cleanup. configure's ESC
// handler is gated on its private form-mode state, so each non-form
// mode brings its own ESC route.

const ATTR_PANEL      = 'data-misp-configure-root';
const ATTR_BODY       = 'data-misp-configure-body';
const ATTR_TITLE      = 'data-misp-configure-title';
const ATTR_MODE       = 'data-misp-configure-mode';
const ATTR_BACKDROP   = 'data-misp-configure-backdrop';
const ATTR_BOARD_ROOT = 'data-misp-board-root';
const ATTR_EXPORT_URL = 'data-misp-board-export-url';
const ATTR_SAVE_URL   = 'data-misp-board-save-url';

// ---- small DOM helper (self-contained; no cross-module import) ----

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2), v);
      } else if (v !== null && v !== undefined && v !== false) {
        node.setAttribute(k, v === true ? '' : v);
      }
    }
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function panelEls() {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  const body     = panel?.querySelector(`[${ATTR_BODY}]`);
  const title    = panel?.querySelector(`[${ATTR_TITLE}]`);
  return { panel, backdrop, body, title };
}

function boardRoot() {
  return document.querySelector(`[${ATTR_BOARD_ROOT}]`);
}

// Open the panel in the given mode with a fresh, empty body. Returns
// the body element (caller fills it) or null if the panel is absent.
function openPanel(mode, titleText) {
  const { panel, backdrop, body, title } = panelEls();
  if (!panel || !backdrop || !body) {
    console.warn('[misp-dashboard] configure panel markup not found');
    return null;
  }
  panel.setAttribute(ATTR_MODE, mode);
  if (title) title.textContent = titleText;
  body.replaceChildren();
  backdrop.removeAttribute('hidden');
  panel.removeAttribute('hidden');
  panel.classList.add('is-open');
  return body;
}

function closePanel() {
  const { panel, backdrop } = panelEls();
  if (!panel) return;
  panel.classList.remove('is-open');
  panel.setAttribute('hidden', '');
  if (backdrop) backdrop.setAttribute('hidden', '');
}

// ---- data-shape helpers ----

// Reduce any recognised configuration blob to the bare widget array
// the board persists (DD-05). Tolerates what Export emits (a bare
// array) plus the legacy export envelopes so a config copied from an
// older MISP instance still imports.
function normaliseToWidgetArray(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === 'object') {
    // v1 export: { UserSetting: { value: <array | json-string> } }
    if (parsed.UserSetting && parsed.UserSetting.value !== undefined) {
      const v = parsed.UserSetting.value;
      return Array.isArray(v) ? v : JSON.parse(v);
    }
    // form-post envelope: { Dashboard: { value: <array | json-string> } }
    if (parsed.Dashboard && parsed.Dashboard.value !== undefined) {
      const v = parsed.Dashboard.value;
      return Array.isArray(v) ? v : JSON.parse(v);
    }
    // explicit { widgets: [...] }
    if (Array.isArray(parsed.widgets)) return parsed.widgets;
  }
  throw new Error('Unrecognised dashboard configuration shape.');
}

// ---- export ----

export async function openExportConfig() {
  const body = openPanel('export', 'Export configuration');
  if (!body) return;

  body.appendChild(
    el('p', { class: 'misp-configio-status' }, 'Loading configuration…'),
  );

  const exportUrl = boardRoot()?.getAttribute(ATTR_EXPORT_URL);
  if (!exportUrl) {
    renderExportError(body, 'Export endpoint is not configured.');
    return;
  }
  try {
    const resp = await fetch(exportUrl, {
      headers: {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-Token': (window.csrfToken || ''),
      },
      credentials: 'same-origin',
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const widgets = normaliseToWidgetArray(data);
    renderExportBody(body, JSON.stringify(widgets, null, 2));
  } catch (err) {
    renderExportError(body, `Could not load configuration: ${err.message}`);
  }
}

function renderExportError(body, message) {
  body.replaceChildren(
    el('p', { class: 'misp-configio-error', role: 'alert' }, message),
    el('div', { class: 'misp-configio-actions' },
      el('button', {
        type: 'button',
        class: 'misp-dashboard-btn',
        onclick: closePanel,
      }, 'Close'),
    ),
  );
}

function renderExportBody(body, json) {
  const textarea = el('textarea', {
    class: 'misp-configio-textarea',
    readonly: true,
    spellcheck: 'false',
    'aria-label': 'Dashboard configuration JSON',
  });
  textarea.value = json;

  const copyBtn = el('button', {
    type: 'button',
    class: 'misp-dashboard-btn misp-dashboard-btn-primary',
  }, 'Copy to clipboard');
  copyBtn.addEventListener('click', async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(textarea.value);
      } else {
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
      }
      copyBtn.textContent = 'Copied';
      setTimeout(() => { copyBtn.textContent = 'Copy to clipboard'; }, 1500);
    } catch (_) {
      // Clipboard blocked — fall back to selecting so the user can ⌘/Ctrl-C.
      textarea.focus();
      textarea.select();
    }
  });

  body.replaceChildren(
    el('p', { class: 'misp-configio-help' },
      'Copy and share this configuration. Sanitise it first so nothing '
      + 'sensitive is shared. Paste it into Import on another dashboard.'),
    textarea,
    el('div', { class: 'misp-configio-actions' },
      el('button', {
        type: 'button',
        class: 'misp-dashboard-btn',
        onclick: closePanel,
      }, 'Close'),
      copyBtn,
    ),
  );
  // Pre-select so a plain Ctrl/⌘-C works even before clicking Copy.
  textarea.focus();
  textarea.select();
}

// ---- import ----

export function openImportConfig() {
  const body = openPanel('import', 'Import configuration');
  if (!body) return;
  renderImportBody(body);
}

function renderImportBody(body) {
  const textarea = el('textarea', {
    class: 'misp-configio-textarea',
    spellcheck: 'false',
    placeholder: 'Paste a dashboard configuration JSON here…',
    'aria-label': 'Dashboard configuration JSON to import',
  });

  const status = el('p', { class: 'misp-configio-status', role: 'status' });

  const loadBtn = el('button', {
    type: 'button',
    class: 'misp-dashboard-btn misp-dashboard-btn-primary',
  }, 'Load configuration');

  loadBtn.addEventListener('click', async () => {
    status.className = 'misp-configio-status';
    status.textContent = '';
    let widgets;
    try {
      widgets = normaliseToWidgetArray(JSON.parse(textarea.value));
    } catch (err) {
      status.className = 'misp-configio-error';
      status.textContent = `Invalid configuration: ${err.message}`;
      textarea.focus();
      return;
    }
    const saveUrl = boardRoot()?.getAttribute(ATTR_SAVE_URL);
    if (!saveUrl) {
      status.className = 'misp-configio-error';
      status.textContent = 'Import endpoint is not configured.';
      return;
    }
    loadBtn.disabled = true;
    status.textContent = 'Importing…';
    try {
      const reqBody = new URLSearchParams({
        'Dashboard[value]': JSON.stringify(widgets),
      });
      const resp = await fetch(saveUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-CSRF-Token': (window.csrfToken || ''),
        },
        body: reqBody,
        credentials: 'same-origin',
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const result = await resp.json().catch(() => ({}));
      if (result && (result.saved === false || result.errors)) {
        throw new Error(result.message || 'Settings could not be updated.');
      }
      // Reload so the board re-renders from the imported config —
      // simplest robust refresh, and matches the v1 import redirect.
      window.location.reload();
    } catch (err) {
      loadBtn.disabled = false;
      status.className = 'misp-configio-error';
      status.textContent = `Import failed: ${err.message}`;
    }
  });

  body.replaceChildren(
    el('p', { class: 'misp-configio-help' },
      'Paste a configuration JSON exported from this or another MISP '
      + 'dashboard. Loading replaces your current dashboard layout.'),
    textarea,
    status,
    el('div', { class: 'misp-configio-actions' },
      el('button', {
        type: 'button',
        class: 'misp-dashboard-btn',
        onclick: closePanel,
      }, 'Cancel'),
      loadBtn,
    ),
  );
  textarea.focus();
}

// ---- lifecycle (mirrors gallery.module.mjs) ----

function init() {
  const panel = document.querySelector(`[${ATTR_PANEL}]`);
  if (!panel) return;

  // ESC for our modes — configure.module.mjs's ESC handler bails when
  // its private form-mode state is null.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const mode = panel.getAttribute(ATTR_MODE);
    if (mode !== 'export' && mode !== 'import') return;
    e.preventDefault();
    closePanel();
  });

  // The panel's `hidden` attribute is the canonical close signal,
  // flipped by configure.module.mjs's closeConfigure (backdrop / ✕ /
  // Cancel) and our closePanel. Clear our mode + body on hide so a
  // later open (any mode) starts clean.
  const observer = new MutationObserver((muts) => {
    for (const m of muts) {
      if (m.attributeName !== 'hidden') continue;
      if (panel.hasAttribute('hidden')) {
        const mode = panel.getAttribute(ATTR_MODE);
        if (mode === 'export' || mode === 'import') {
          panel.removeAttribute(ATTR_MODE);
          const body = panel.querySelector(`[${ATTR_BODY}]`);
          if (body) body.replaceChildren();
        }
      }
    }
  });
  observer.observe(panel, { attributes: true, attributeFilter: ['hidden'] });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
