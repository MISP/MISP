// dashboard-v2 BoardModule — Phase 0.3 prototype.
//
// Implements the §8.5 hook contract: scans the DOM for the stable
// data-* attributes, hydrates a GridModule with the discovered tiles,
// wires the widget/board action buttons, AJAX-renders each widget
// via /dashboards/proto/renderWidget, and dispatches custom events on
// the board root so theme JS can layer in extra behaviour without
// forking this file.
//
// Stable contract (do not break without a deprecation note):
//
//   Markup attributes
//     [data-misp-board-root]                       — required.
//       data-misp-board-mode="view"|"edit"
//       data-misp-board-renderwidget-url="..."
//
//     [data-misp-widget]                           — one widget tile.
//       data-widget-name="..."                     — class name
//       data-widget-instance-id="..."              — stable id
//       data-widget-config="..."                   — JSON-encoded
//       data-position-{x,y,w,h}                    — initial layout
//
//     [data-misp-widget-content]                   — render target.
//
//     [data-misp-widget-action="refresh|configure|remove|export-json|export-csv"]
//
//     [data-misp-board-action="toggle-mode|save|discard|add-widget|set-scope|pause-refresh"]
//
//   Custom events on the board root
//     misp-board:mode-changed      detail: { mode }
//     misp-board:widget-rendered   detail: { instanceId, widgetName }
//     misp-board:widget-error      detail: { instanceId, widgetName, error }
//     misp-board:saved             detail: { layout }
//     misp-board:scope-changed     detail: { scope }   (Phase 0.3 commit 8)

import { Grid } from './grid/grid.module.mjs';
import { initChartsIn, disposeChartsIn } from './charts/charts.module.mjs';
import { openConfigure } from './configure.module.mjs';
import { initToolbar, refresh as refreshToolbar } from './toolbar.module.mjs';

const ATTR_BOARD_ROOT       = 'data-misp-board-root';
const ATTR_BOARD_MODE       = 'data-misp-board-mode';
const ATTR_RENDER_URL       = 'data-misp-board-renderwidget-url';
const ATTR_WIDGET           = 'data-misp-widget';
const ATTR_WIDGET_NAME      = 'data-widget-name';
const ATTR_WIDGET_INSTANCE  = 'data-widget-instance-id';
const ATTR_WIDGET_CONFIG    = 'data-widget-config';
const ATTR_WIDGET_CONTENT   = 'data-misp-widget-content';
const ATTR_WIDGET_ACTION    = 'data-misp-widget-action';
const ATTR_BOARD_ACTION     = 'data-misp-board-action';
const ATTR_DEBUG_READOUT    = 'data-misp-debug-readout';

class Board {
  constructor(rootEl) {
    this.root = rootEl;
    this.renderUrl = rootEl.getAttribute(ATTR_RENDER_URL);
    this.mode = rootEl.getAttribute(ATTR_BOARD_MODE) || 'view';
    this.grid = null;
    this._wireBoardActions();
    this._wireWidgetActions();
    this._init();
  }

  // ---- boot ----

  _init() {
    // Discover widgets and hand them to GridModule.
    this.grid = new Grid(this.root, {
      cols: parseInt(getComputedStyle(this.root).getPropertyValue('--misp-dash-grid-cols')) || 12,
      rowHeight: parseInt(getComputedStyle(this.root).getPropertyValue('--misp-dash-grid-row-h')) || 80,
      gap: parseInt(getComputedStyle(this.root).getPropertyValue('--misp-dash-grid-gap')) || 8,
    });

    const tiles = [...this.root.querySelectorAll(`[${ATTR_WIDGET}]`)];
    for (const el of tiles) {
      const id = el.getAttribute(ATTR_WIDGET_INSTANCE);
      const x  = parseInt(el.getAttribute('data-position-x') || '0', 10);
      const y  = parseInt(el.getAttribute('data-position-y') || '0', 10);
      const w  = parseInt(el.getAttribute('data-position-w') || '4', 10);
      const h  = parseInt(el.getAttribute('data-position-h') || '3', 10);

      // GridModule manages the tile's grid placement; we hand it the
      // wrapper element. Position fix-ups (PRD §7.1: `width/height → w/h`)
      // happen when the server reads the blob; the markup is already
      // in v2 form here.
      el.remove();                              // detach so Grid can re-place
      this.grid.addTile({ id, x, y, w, h, el });
      this._renderWidget(el);                   // kick off AJAX render
    }

    this._updateDebugReadout();

    // Mount the bulk-edit toolbar for any canonical types declared
    // on this board. The toolbar walks declarer widgets on commit
    // and re-renders each via the same path used for refresh.
    initToolbar(this.root, {
      onWidgetChange: (widgetEl) => this._renderWidget(widgetEl),
    });
  }

  // ---- mode ----

  setMode(mode) {
    if (mode !== 'view' && mode !== 'edit') return;
    if (this.mode === mode) return;
    this.mode = mode;
    this.root.setAttribute(ATTR_BOARD_MODE, mode);
    this._dispatchEvent('mode-changed', { mode });
    // Keep the toggle button's aria-pressed state in sync.
    const btn = document.querySelector(`[${ATTR_BOARD_ACTION}="toggle-mode"]`);
    if (btn) btn.setAttribute('aria-pressed', mode === 'edit' ? 'true' : 'false');
  }

  // ---- widget rendering ----

  async _renderWidget(widgetEl) {
    const id      = widgetEl.getAttribute(ATTR_WIDGET_INSTANCE);
    const name    = widgetEl.getAttribute(ATTR_WIDGET_NAME);
    const config  = widgetEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}';
    const target  = widgetEl.querySelector(`[${ATTR_WIDGET_CONTENT}]`);
    if (!target) return;

    try {
      const body = new URLSearchParams({ widget: name, config });
      const resp = await fetch(`${this.renderUrl}/${encodeURIComponent(id)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'text/html',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body,
        credentials: 'same-origin',
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const html = await resp.text();
      // Dispose any charts in the previous render *before* innerHTML
      // replacement so ECharts instances + their global listeners
      // don't leak when a widget is refreshed.
      disposeChartsIn(target);
      target.innerHTML = html;
      initChartsIn(target);
      this._dispatchEvent('widget-rendered', { instanceId: id, widgetName: name });
    } catch (err) {
      disposeChartsIn(target);
      target.innerHTML = `<div class="misp-widget-error" role="alert">${escapeHtml(String(err))}</div>`;
      this._dispatchEvent('widget-error', { instanceId: id, widgetName: name, error: String(err) });
    }
  }

  _findWidgetEl(target) {
    return target.closest(`[${ATTR_WIDGET}]`);
  }

  // ---- action wiring ----

  _wireBoardActions() {
    this.root.ownerDocument.addEventListener('click', (e) => {
      const trigger = e.target.closest(`[${ATTR_BOARD_ACTION}]`);
      if (!trigger) return;
      const action = trigger.getAttribute(ATTR_BOARD_ACTION);
      switch (action) {
        case 'toggle-mode':
          e.preventDefault();
          this.setMode(this.mode === 'view' ? 'edit' : 'view');
          break;
        case 'save':
        case 'discard':
        case 'add-widget':
        case 'set-scope':
        case 'pause-refresh':
          // Stubs — implemented in subsequent Phase 0.3 commits and
          // Phase 1. Logged so a missing handler is visible during
          // prototype review without crashing.
          e.preventDefault();
          console.info(`[misp-dashboard] board action "${action}" not yet implemented in proto`);
          break;
      }
    });
  }

  _wireWidgetActions() {
    this.root.ownerDocument.addEventListener('click', (e) => {
      const trigger = e.target.closest(`[${ATTR_WIDGET_ACTION}]`);
      if (!trigger) return;
      const widgetEl = this._findWidgetEl(trigger);
      if (!widgetEl) return;
      const action = trigger.getAttribute(ATTR_WIDGET_ACTION);
      switch (action) {
        case 'refresh':
          e.preventDefault();
          this._renderWidget(widgetEl);
          break;
        case 'remove':
          e.preventDefault();
          if (this.mode !== 'edit') return;
          const id = widgetEl.getAttribute(ATTR_WIDGET_INSTANCE);
          // Tear down chart instances inside the tile before the DOM
          // node goes away so ECharts releases its window listeners.
          disposeChartsIn(widgetEl);
          this.grid.removeTile(id);
          this._updateDebugReadout();
          break;
        case 'configure':
          e.preventDefault();
          // Configure form is the DD-06 two-tier side panel; on save
          // it writes the new config back to data-widget-config and
          // returns the widget element here so we can re-render with
          // the new shape. Persistence to UserSetting:dashboard is
          // Phase 1 task ("per-widget POST to /updateSettings").
          openConfigure(widgetEl, (savedEl) => {
            this._renderWidget(savedEl);
            // The save may have added or removed a canonical-type
            // declaration, or moved this widget toward / away from
            // "(mixed)" with its peers — the toolbar must refresh.
            refreshToolbar(this.root);
          });
          break;
        case 'export-json':
        case 'export-csv':
          // Phase 5 — drill-down + export wiring.
          e.preventDefault();
          console.info(`[misp-dashboard] widget action "${action}" not yet implemented in proto`);
          break;
      }
    });
  }

  // ---- events ----

  _dispatchEvent(name, detail) {
    this.root.dispatchEvent(new CustomEvent(`misp-board:${name}`, {
      detail, bubbles: true, cancelable: false,
    }));
  }

  // ---- debug readout (Phase 0.3 prototype only) ----

  _updateDebugReadout() {
    const readout = document.querySelector(`[${ATTR_DEBUG_READOUT}]`);
    if (!readout || !this.grid) return;
    readout.textContent = JSON.stringify(this.grid.serialize());
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Boot when DOM is ready.
function boot() {
  const root = document.querySelector(`[${ATTR_BOARD_ROOT}]`);
  if (!root) return;
  const board = new Board(root);
  // Refresh debug readout on grid commits so users can see layout changes.
  new MutationObserver(() => board._updateDebugReadout())
    .observe(root, { attributes: true, subtree: true, attributeFilter: ['style'] });
  // Expose for ad-hoc poking from devtools.
  window.MISPBoard = board;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
