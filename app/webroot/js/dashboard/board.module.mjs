// BoardModule.
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
import { initMenuButtons } from './menu-button.module.mjs';

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
    this.saveUrl  = rootEl.getAttribute('data-misp-board-save-url');
    this.mode = rootEl.getAttribute(ATTR_BOARD_MODE) || 'view';
    this.grid = null;
    this._saveTimer = null;
    // Edit-mode staging state (DD-05 "Layout-only atomic save"):
    //   _editSnapshot.positions  serialized layout at edit-mode entry
    //   _editSnapshot.removedTiles  Map<id, el> for tiles removed during
    //                               this edit session — held in JS so
    //                               Discard can re-add them
    //   _layoutDirty  true after any staged drag / resize / remove
    // When in view mode these are null/false.
    this._editSnapshot = null;
    this._layoutDirty = false;
    this._wireBoardActions();
    this._wireWidgetActions();
    this._init();
  }

  // ---- persistence ----

  /**
   * Serialise the current board state to the v2 widget shape and
   * POST it to /dashboards/updateSettings. Debounced 50ms so the
   * toolbar's per-declarer callback (fires N times for an N-widget
   * bulk commit) collapses to a single network round-trip.
   */
  _scheduleSave() {
    if (!this.saveUrl) return;
    if (this._saveTimer) clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => this._saveLayout(), 50);
  }

  /**
   * DD-05 layout-only atomic save. Drag / resize / remove (and Add
   * Widget when it lands) call this; configure-form Save and toolbar
   * bulk-edits stay on the immediate `_scheduleSave()` path because
   * per DD-05 they're independent of edit-mode layout saves.
   *
   * In edit mode the change stays client-side until the user clicks
   * the Save button (→ _commitEdit) or the Discard button (→
   * _discardEdit). In view mode (e.g. a configure-form save that
   * also mutated the widget's tile via the same callback) the change
   * goes through the same 50ms-debounced save path as before.
   *
   * Known limitation (documented for the dedicated task): if the user
   * triggers a configure-form Save *while* layout edits are staged in
   * edit mode, the underlying whole-blob _saveLayout commits both the
   * widget config change AND the staged layout. The DD-05 ideal is a
   * per-widget POST that leaves the rest of the blob alone — landing
   * in a separate Phase 2 task ("Configure-form Save: per-widget POST
   * to /dashboards/updateSettings...").
   */
  _stageOrSave() {
    if (this.mode === 'edit') {
      this._layoutDirty = true;
      return;
    }
    this._scheduleSave();
  }

  async _saveLayout() {
    if (!this.grid || !this.saveUrl) return false;
    const positions = this.grid.serialize();
    const widgets = [];
    for (const p of positions) {
      const wEl = this.root.querySelector(
        `[${ATTR_WIDGET_INSTANCE}="${CSS.escape(p.id)}"]`,
      );
      if (!wEl) continue;
      let config = {};
      try {
        config = JSON.parse(wEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}');
      } catch (_) { /* keep empty */ }
      widgets.push({
        instance_id: p.id,
        widget: wEl.getAttribute(ATTR_WIDGET_NAME),
        alias:  wEl.getAttribute('data-widget-alias') || null,
        config,
        position: { x: p.x, y: p.y, w: p.w, h: p.h },
      });
    }
    try {
      const body = new URLSearchParams({
        'Dashboard[value]': JSON.stringify(widgets),
      });
      const resp = await fetch(this.saveUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body,
        credentials: 'same-origin',
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      this._dispatchEvent('saved', { count: widgets.length });
      return true;
    } catch (err) {
      console.warn('[misp-dashboard] save failed', err);
      this._dispatchEvent('save-failed', { error: String(err) });
      return false;
    }
  }

  // ---- boot ----

  _init() {
    // Discover widgets and hand them to GridModule.
    this.grid = new Grid(this.root, {
      cols: parseInt(getComputedStyle(this.root).getPropertyValue('--misp-dash-grid-cols')) || 12,
      rowHeight: parseInt(getComputedStyle(this.root).getPropertyValue('--misp-dash-grid-row-h')) || 80,
      gap: parseInt(getComputedStyle(this.root).getPropertyValue('--misp-dash-grid-gap')) || 8,
      // Persist drag/resize commits. Grid fires this only when at
      // least one tile's x/y/w/h actually changed, so a tile dropped
      // back at its origin doesn't trigger any side effect. In edit
      // mode the change is staged via _stageOrSave (Save button
      // flushes; Discard reverts to the snapshot). In view mode the
      // change goes through the 50ms-debounced save path so cascade-
      // affected tiles or multi-drop sequences coalesce.
      onCommit: () => this._stageOrSave(),
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
    // on this board. The toolbar walks declarer widgets on commit,
    // re-renders each via the same path used for refresh, and asks
    // the board to persist (debounced so an N-declarer commit
    // collapses to a single round-trip).
    initToolbar(this.root, {
      onWidgetChange: (widgetEl) => {
        this._renderWidget(widgetEl);
        this._scheduleSave();
      },
    });
  }

  // ---- mode ----

  setMode(mode) {
    if (mode !== 'view' && mode !== 'edit') return;
    if (this.mode === mode) return;
    const prevMode = this.mode;
    this.mode = mode;
    this.root.setAttribute(ATTR_BOARD_MODE, mode);
    // Edit-mode staging snapshot (DD-05 atomic save):
    //   - view → edit  capture the current layout + reset dirty flag
    //                  so Discard / Save have a reference to compare
    //                  against and rewind to.
    //   - edit → view  release the snapshot; tile DOM elements we
    //                  held alive for a possible Discard are gc'd.
    if (mode === 'edit' && prevMode === 'view') {
      this._editSnapshot = {
        positions: this.grid ? this.grid.serialize() : [],
        removedTiles: new Map(),
      };
      this._layoutDirty = false;
    } else if (mode === 'view' && prevMode === 'edit') {
      this._editSnapshot = null;
      this._layoutDirty = false;
    }
    this._dispatchEvent('mode-changed', { mode });
    // Keep the toggle button's aria-pressed state in sync.
    const btn = document.querySelector(`[${ATTR_BOARD_ACTION}="toggle-mode"]`);
    if (btn) btn.setAttribute('aria-pressed', mode === 'edit' ? 'true' : 'false');
  }

  /**
   * Save button (edit mode): flush any pending debounce timer, POST
   * the current layout, and on success drop back to view mode. On
   * failure stay in edit mode so the user can retry — the
   * 'save-failed' event fired by _saveLayout signals the error path
   * to any theme JS listening.
   */
  async _commitEdit() {
    if (this.mode !== 'edit') return;
    if (this._saveTimer) {
      clearTimeout(this._saveTimer);
      this._saveTimer = null;
    }
    // Pending removed tiles' chart instances were kept alive (in case
    // Discard restored them). Save is the commit point — release
    // ECharts now so its global instance map doesn't leak.
    if (this._editSnapshot) {
      for (const el of this._editSnapshot.removedTiles.values()) {
        disposeChartsIn(el);
      }
    }
    const ok = await this._saveLayout();
    if (ok) this.setMode('view');
  }

  /**
   * Discard button (edit mode): revert the layout to the entry
   * snapshot. Confirm via window.confirm() if any staged change
   * (drag / resize / remove) is dirty. Restores positions of tiles
   * that still exist, re-adds any removed tiles (held in
   * _editSnapshot.removedTiles), and removes any newly-added tiles
   * not present in the snapshot (Add Widget flow not yet implemented
   * but covered for the future). Then drops back to view mode.
   */
  _discardEdit() {
    if (this.mode !== 'edit' || !this._editSnapshot) return;
    if (this._layoutDirty) {
      const ok = window.confirm(
        'Discard pending layout changes? This cannot be undone.',
      );
      if (!ok) return;
    }
    const { positions, removedTiles } = this._editSnapshot;
    const snapshotIds = new Set(positions.map(p => p.id));
    const currentIds = new Set(this.grid.serialize().map(p => p.id));

    // Remove tiles that exist now but were not in the snapshot — they
    // were added during this edit session. (Add Widget hasn't shipped
    // yet, but this is the contract.)
    for (const id of currentIds) {
      if (!snapshotIds.has(id)) {
        const wEl = this.root.querySelector(
          `[${ATTR_WIDGET_INSTANCE}="${CSS.escape(id)}"]`,
        );
        if (wEl) disposeChartsIn(wEl);
        this.grid.removeTile(id);
      }
    }

    // Restore positions of tiles that still exist; re-add tiles that
    // were removed during this edit session.
    for (const p of positions) {
      if (currentIds.has(p.id)) {
        this.grid.updateTile(p.id, { x: p.x, y: p.y, w: p.w, h: p.h });
      } else if (removedTiles.has(p.id)) {
        const el = removedTiles.get(p.id);
        // addTile clears existing inline styles via _applyTileStyle.
        this.grid.addTile({ id: p.id, x: p.x, y: p.y, w: p.w, h: p.h, el });
        this._renderWidget(el);
      }
    }
    this._updateDebugReadout();
    this.setMode('view');
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
          e.preventDefault();
          this._commitEdit();
          break;
        case 'discard':
          e.preventDefault();
          this._discardEdit();
          break;
        case 'add-widget':
        case 'set-scope':
        case 'pause-refresh':
          // Stubs — implemented in subsequent Phase 2 / Phase 5 commits.
          // Logged so a missing handler is visible during prototype
          // review without crashing.
          e.preventDefault();
          console.info(`[misp-dashboard] board action "${action}" not yet implemented`);
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
        case 'remove': {
          e.preventDefault();
          if (this.mode !== 'edit') return;
          const id = widgetEl.getAttribute(ATTR_WIDGET_INSTANCE);
          // In edit mode, stash the tile element so Discard can re-add
          // it. Chart instances stay alive too — the tile is detached
          // from the DOM via grid.removeTile (which calls .el.remove()
          // on it). The element is still a valid DOM node, just no
          // longer in the document; charts inside it remain bound to
          // their own canvases. If Discard never re-adds it, the GC
          // collects everything when the snapshot is released on
          // setMode('view'). If the user clicks Save, the snapshot is
          // released and the stale references go too.
          if (this._editSnapshot) {
            this._editSnapshot.removedTiles.set(id, widgetEl);
          } else {
            // Defensive — shouldn't happen because remove is edit-mode-
            // gated, but if the snapshot is missing, fall back to the
            // old destructive path so the chart-dispose still runs.
            disposeChartsIn(widgetEl);
          }
          this.grid.removeTile(id);
          this._updateDebugReadout();
          // removeTile bypasses Grid._commit (it directly mutates
          // this.tiles), so the onCommit hook used by drag/resize
          // doesn't fire here — stage explicitly (or save in view mode).
          this._stageOrSave();
          break;
        }
        case 'configure':
          e.preventDefault();
          // Configure form is the DD-06 two-tier side panel.
          //   onSave    - the user clicked Save. Re-render with the
          //               new config, refresh the toolbar (the change
          //               may have moved this widget toward / away
          //               from "(mixed)" with its peers), and POST
          //               the whole layout to UserSetting:dashboard.
          //   onPreview - live-preview tick (debounced 250ms per
          //               DD-06). data-widget-config already updated;
          //               re-render the body without persisting.
          openConfigure(widgetEl, {
            onSave: (savedEl) => {
              this._renderWidget(savedEl);
              refreshToolbar(this.root);
              this._scheduleSave();
            },
            onPreview: (previewEl) => {
              this._renderWidget(previewEl);
            },
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
  // Hydrate any header menu buttons (DD-08 "⋯ More" dropdown). Run
  // before the board-root check so the dropdown still works on any
  // dashboard-layout page that doesn't render a board grid.
  initMenuButtons();

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
