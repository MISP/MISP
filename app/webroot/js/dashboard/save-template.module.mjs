// Dashboard "Save as template" slide-in module.
//
// Opens the shared configure side panel in a new mode — "save-template" —
// reusing the panel chrome the same way config-io.module.mjs / gallery.module
// .mjs do (backdrop, ✕, ESC, the `hidden`-attribute close signal). This keeps
// the feature theme-independent: it depends only on the dashboard's own shared
// markup + CSS, not on either theme's global modal (DD-08).
//
// Replaces the old full-page redirect to /dashboards/saveTemplate: instead we
//   1. fetch that action's SERVER-RENDERED form via an XHR GET (it returns the
//      bare form partial — incl. its CakePHP Security/_Token set — because the
//      controller has an is('ajax') branch); inject it into the panel body;
//   2. on submit, POST the form (token and all) with Accept: application/json
//      so the action's existing REST branch returns a clean saved/failed JSON
//      instead of the HTML redirect-to-gallery (which can't signal failure);
//   3. on success, stay on the dashboard and show an inline confirmation —
//      saving a template does NOT change the current board, so no reload.
//
// The CSRF token is single-use (Security::$csrfUseOnce = true), so a failed
// submit re-fetches the form to re-mint the token before the user retries.
//
// Coupling with configure.module.mjs mirrors config-io.module.mjs: the shared
// ✕ / backdrop close chain flips the panel's `hidden` attribute; a
// MutationObserver on it runs our cleanup. configure's ESC handler is gated on
// its private form-mode state, so this mode brings its own ESC route.

const ATTR_PANEL             = 'data-misp-configure-root';
const ATTR_BODY              = 'data-misp-configure-body';
const ATTR_TITLE             = 'data-misp-configure-title';
const ATTR_MODE              = 'data-misp-configure-mode';
const ATTR_BACKDROP          = 'data-misp-configure-backdrop';
const ATTR_BOARD_ROOT        = 'data-misp-board-root';
const ATTR_SAVE_TEMPLATE_URL = 'data-misp-board-savetemplate-url';
const MODE                   = 'save-template';
const NAME_FIELD             = 'data[Dashboard][name]';

// The save-template action URL, remembered across an open so a failed submit
// can re-fetch the form (re-minting the single-use CSRF token).
let formUrl = null;

// ---- small DOM helper (self-contained; mirrors config-io.module.mjs) ----

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

// listTemplates lives next to saveTemplate on the same controller.
function listTemplatesUrl() {
  return formUrl ? formUrl.replace(/\/saveTemplate(\/.*)?$/, '/listTemplates') : '#';
}

// ---- open + load ----

export async function openSaveTemplate() {
  const body = openPanel(MODE, 'Save dashboard as template');
  if (!body) return;
  formUrl = boardRoot()?.getAttribute(ATTR_SAVE_TEMPLATE_URL) || null;
  if (!formUrl) {
    renderError(body, 'The save-as-template endpoint is not configured.');
    return;
  }
  await loadForm(body);
}

async function loadForm(body) {
  body.replaceChildren(
    el('p', { class: 'misp-configio-status' }, 'Loading…'),
  );
  try {
    const resp = await fetch(formUrl, {
      headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'text/html' },
      credentials: 'same-origin',
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const tpl = document.createElement('template');
    tpl.innerHTML = await resp.text();
    const form = tpl.content.querySelector('form');
    if (!form) throw new Error('form markup not found in response');
    wireForm(form, body);
    body.replaceChildren(form);
    const name = form.querySelector(`[name="${NAME_FIELD}"]`);
    if (name) name.focus();
  } catch (err) {
    renderError(body, `Could not load the form: ${err.message}`);
  }
}

function wireForm(form, body) {
  // The browser runs native constraint validation before firing `submit`, so
  // this handler only runs once the required name is filled.
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submitForm(form, body);
  });
  // The form's own Cancel link would otherwise navigate to the gallery — keep
  // us in place and just close the panel.
  const cancel = form.querySelector('[data-misp-template-form-action="cancel"]');
  if (cancel) {
    cancel.addEventListener('click', (e) => { e.preventDefault(); closePanel(); });
  }
}

async function submitForm(form, body) {
  if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;
  const submitBtn = form.querySelector('[data-misp-template-form-action="submit"]');
  const fd = new FormData(form);
  const name = String(fd.get(NAME_FIELD) || '').trim();
  if (submitBtn) submitBtn.disabled = true;
  try {
    const resp = await fetch(form.getAttribute('action') || form.action, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(fd),
      credentials: 'same-origin',
    });
    const result = await resp.json().catch(() => ({}));
    const ok = resp.ok && result && result.saved !== false && !result.errors;
    if (!ok) {
      throw new Error(
        (result && (result.message || result.errors)) || `HTTP ${resp.status}`,
      );
    }
    renderSuccess(body, name);
  } catch (err) {
    // Single-use CSRF token is now spent — reload the form (fresh token) and
    // surface the error above it so a retry can succeed.
    if (submitBtn) submitBtn.disabled = false;
    await loadForm(body);
    const reloaded = panelEls().body;
    if (reloaded) {
      reloaded.prepend(
        el('p', { class: 'misp-configio-error', role: 'alert' },
          `Could not save the template: ${err.message}`),
      );
    }
  }
}

function renderSuccess(body, name) {
  body.replaceChildren(
    el('div', { class: 'misp-template-saved' },
      el('p', { class: 'misp-template-saved-msg' },
        name
          ? `✓  Saved “${name}” as a template.`
          : '✓  Saved as a template.'),
      el('p', { class: 'misp-configio-help' },
        'Your current dashboard is unchanged — the template is now available '
        + 'in the gallery.'),
      el('div', { class: 'misp-configio-actions' },
        el('a', {
          class: 'misp-dashboard-btn',
          href: listTemplatesUrl(),
        }, 'Browse templates'),
        el('button', {
          type: 'button',
          class: 'misp-dashboard-btn misp-dashboard-btn-primary',
          onclick: closePanel,
        }, 'Close'),
      ),
    ),
  );
}

function renderError(body, message) {
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

// ---- lifecycle (mirrors config-io.module.mjs) ----

function init() {
  const panel = document.querySelector(`[${ATTR_PANEL}]`);
  if (!panel) return;

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (panel.getAttribute(ATTR_MODE) !== MODE) return;
    e.preventDefault();
    closePanel();
  });

  const observer = new MutationObserver((muts) => {
    for (const m of muts) {
      if (m.attributeName !== 'hidden') continue;
      if (panel.hasAttribute('hidden') && panel.getAttribute(ATTR_MODE) === MODE) {
        panel.removeAttribute(ATTR_MODE);
        const body = panel.querySelector(`[${ATTR_BODY}]`);
        if (body) body.replaceChildren();
        formUrl = null;
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
