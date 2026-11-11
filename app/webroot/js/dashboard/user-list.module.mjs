// UserList interactive behaviour (dashboard v2, DD-36).
//
// Wires the two opt-in affordances the UserList render kind can emit:
//
//   1. A client-side filter box (`[data-misp-user-search]`): hides rows
//      whose name/meta don't match. The term is kept PER WIDGET INSTANCE
//      and re-applied after every render, because the board replaces the
//      widget body wholesale on each auto-refresh (wiping the input).
//
//   2. Per-row action buttons (`[data-misp-user-action-url]`): open a
//      confirm form in the dashboard's OWN side panel (the gallery/
//      settings panel) via a GET, then POST it. On success the source
//      widget is re-rendered from authoritative server data.
//
// Theme-independent by construction: it depends only on the dashboard's
// own panel markup + the board's `misp-board:widget-rendered` /
// `misp-board:render-widget` events — never on either theme's modal JS
// (the default theme's jQuery `genericPopover` and Overmind's `openModal`
// are mutually incompatible; see DD-08 / DD-10).
//
// CSRF: the GET form carries a fresh BetterSecurity token (Form->create);
// the POST submits the form's FormData (token included) back to the same
// endpoint. Both requests use `Accept: text/html` so MISP does NOT treat
// them as REST — an isJson()/isRest() request would disable csrfCheck,
// bypassing the token. The endpoint returns JSON regardless.

const ATTR_BOARD_ROOT     = 'data-misp-board-root';
const ATTR_PANEL          = 'data-misp-configure-root';
const ATTR_BODY           = 'data-misp-configure-body';
const ATTR_TITLE          = 'data-misp-configure-title';
const ATTR_BACKDROP       = 'data-misp-configure-backdrop';
const ATTR_MODE           = 'data-misp-configure-mode';
const ATTR_LIST           = 'data-misp-user-list';
const ATTR_INSTANCE       = 'data-misp-instance';
const ATTR_SEARCH         = 'data-misp-user-search';
const ATTR_ACTION_URL     = 'data-misp-user-action-url';
const MODE                = 'confirm';

// Filter terms kept across auto-refresh re-renders, keyed by instance id.
const searchTerms = new Map();
// Wired-once guard for the shared panel's ESC + close-cleanup observer.
let panelWired = false;

// ---- small DOM helpers (self-contained; no cross-module import) ----

function boardRoot() {
  return document.querySelector(`[${ATTR_BOARD_ROOT}]`);
}

function panelEls() {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  const body     = panel ? panel.querySelector(`[${ATTR_BODY}]`) : null;
  const title    = panel ? panel.querySelector(`[${ATTR_TITLE}]`) : null;
  return { panel, backdrop, body, title };
}

function statusNode(cls, text) {
  const p = document.createElement('p');
  p.className = cls;
  p.textContent = text;
  return p;
}

// ---- client-side search ----

function applyFilter(listEl, term) {
  const t = String(term || '').trim().toLowerCase();
  listEl.querySelectorAll('.misp-user-row').forEach((row) => {
    if (t === '') {
      row.hidden = false;
      return;
    }
    const name = (row.querySelector('.misp-user-name')?.textContent || '').toLowerCase();
    const meta = (row.querySelector('.misp-user-meta')?.textContent || '').toLowerCase();
    row.hidden = !(name.includes(t) || meta.includes(t));
  });
}

function wireSearch(listEl, instanceId) {
  const input = listEl.querySelector(`[${ATTR_SEARCH}]`);
  if (!input) return;
  // Restore + re-apply a term saved before a refresh blew the input away.
  const saved = searchTerms.get(instanceId) || '';
  if (saved !== '') {
    input.value = saved;
    applyFilter(listEl, saved);
  }
  input.addEventListener('input', () => {
    searchTerms.set(instanceId, input.value);
    applyFilter(listEl, input.value);
  });
}

// ---- per-row action → confirm panel ----

function closeConfirmPanel() {
  const { panel, backdrop } = panelEls();
  if (panel) {
    panel.classList.remove('is-open');
    panel.setAttribute('hidden', '');
  }
  if (backdrop) backdrop.setAttribute('hidden', '');
}

function openConfirmPanel(actionUrl, instanceId) {
  const { panel, backdrop, body, title } = panelEls();
  if (!panel || !backdrop || !body) {
    console.warn('[misp-dashboard] configure panel markup not found');
    return;
  }
  panel.setAttribute(ATTR_MODE, MODE);
  if (title) title.textContent = 'Invalidate sessions';
  body.replaceChildren(statusNode('misp-user-confirm-loading', 'Loading…'));
  backdrop.removeAttribute('hidden');
  panel.removeAttribute('hidden');
  panel.classList.add('is-open');

  fetch(actionUrl, {
    headers: { 'Accept': 'text/html', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': (window.csrfToken || '') },
    credentials: 'same-origin',
  })
    .then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.text();
    })
    .then((html) => {
      body.innerHTML = html;
      wireConfirmForm(body, actionUrl, instanceId);
    })
    .catch((err) => {
      body.replaceChildren(
        statusNode('misp-user-confirm-sub', `Could not load: ${err.message}`),
      );
    });
}

function wireConfirmForm(body, actionUrl, instanceId) {
  body.querySelectorAll('[data-misp-user-confirm-cancel]').forEach((b) => {
    b.addEventListener('click', closeConfirmPanel);
  });
  const form = body.querySelector('form');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;
    try {
      const resp = await fetch(actionUrl, {
        method: 'POST',
        headers: { 'Accept': 'text/html', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': (window.csrfToken || '') },
        credentials: 'same-origin',
        body: new FormData(form),
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && data && data.saved) {
        closeConfirmPanel();
        // Repaint the source widget from server truth (row gone, counts
        // updated) rather than hand-editing the DOM here.
        if (instanceId) {
          const root = boardRoot();
          if (root) {
            root.dispatchEvent(new CustomEvent('misp-board:render-widget', {
              detail: { instanceId }, bubbles: true,
            }));
          }
        }
      } else {
        const msg = (data && data.errors) ? data.errors : 'Request failed.';
        form.appendChild(statusNode('misp-user-confirm-sub', String(msg)));
        if (submitBtn) submitBtn.disabled = false;
      }
    } catch (err) {
      form.appendChild(statusNode('misp-user-confirm-sub', String(err.message)));
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

function wireActions(listEl, instanceId) {
  listEl.querySelectorAll(`[${ATTR_ACTION_URL}]`).forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const url = btn.getAttribute(ATTR_ACTION_URL);
      if (url) openConfirmPanel(url, instanceId);
    });
  });
}

// ---- per-render wiring (idempotent) ----

function wireList(listEl) {
  // Each render replaces the widget body, so the wrapper is a NEW element;
  // the flag resets naturally. The guard only stops a double-wire when an
  // unrelated widget's render triggers a full re-scan.
  if (listEl.__mispUserWired) return;
  listEl.__mispUserWired = true;
  const instanceId = listEl.getAttribute(ATTR_INSTANCE) || '';
  wireSearch(listEl, instanceId);
  wireActions(listEl, instanceId);
}

function scanAndWire(scope) {
  (scope || document).querySelectorAll(`[${ATTR_LIST}]`).forEach(wireList);
}

// ---- shared panel: ESC + close-cleanup (wired once) ----

function wirePanelOnce() {
  if (panelWired) return;
  const { panel } = panelEls();
  if (!panel) return;
  panelWired = true;

  // ESC closes our confirm mode (configure.module's own ESC is gated on
  // its form state, so it won't act for our mode).
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (panel.getAttribute(ATTR_MODE) === MODE && !panel.hasAttribute('hidden')) {
      closeConfirmPanel();
    }
  });

  // Any close route flips the panel's `hidden` attribute (our cancel/ESC,
  // or the shared ✕ / backdrop handled by configure.module). When it
  // hides out of our mode, clear the mode + body so a stale confirm form
  // can't bleed into a later gallery/configure open.
  new MutationObserver((muts) => {
    for (const m of muts) {
      if (m.attributeName !== 'hidden') continue;
      if (panel.hasAttribute('hidden') && panel.getAttribute(ATTR_MODE) === MODE) {
        panel.removeAttribute(ATTR_MODE);
        const body = panel.querySelector(`[${ATTR_BODY}]`);
        if (body) body.replaceChildren();
      }
    }
  }).observe(panel, { attributes: true, attributeFilter: ['hidden'] });
}

// ---- entry point ----

export function initUserList() {
  const root = boardRoot();
  if (!root) return;
  wirePanelOnce();
  // Subsequent renders / auto-refreshes re-wire the new body.
  root.addEventListener('misp-board:widget-rendered', () => scanAndWire(root));
  // Catch any UserList already painted before this listener attached.
  scanAndWire(root);
}
