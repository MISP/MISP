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
//       data-misp-board-save-url="..."             — whole-blob layout save
//       data-misp-board-widget-save-url="..."      — per-widget config patch
//                                                    (DD-05; layout untouched)
//       data-misp-board-widgets-url="..."          — widget gallery metadata
//       data-misp-board-wrapper-url="..."          — Add Widget placement
//                                                    wrapper HTML render
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
//     misp-board:add-widget-pending  detail: { draftEl, meta }   (Phase 2 Add)
//     misp-board:add-widget-placed   detail: { instanceId, widgetName,
//                                              x, y, w, h }
//     misp-board:add-widget-failed   detail: { error }

import { Grid } from './grid/grid.module.mjs';
import { initChartsIn, disposeChartsIn } from './charts/charts.module.mjs';
import { openConfigure } from './configure.module.mjs';
import { openGallery }   from './gallery.module.mjs';
import {
  initToolbar,
  refresh as refreshToolbar,
  currentValues as currentToolbarValues,
} from './toolbar.module.mjs';
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
    this.widgetSaveUrl = rootEl.getAttribute('data-misp-board-widget-save-url');
    this.wrapperUrl = rootEl.getAttribute('data-misp-board-wrapper-url');
    this.mode = rootEl.getAttribute(ATTR_BOARD_MODE) || 'view';
    this.grid = null;
    this._saveTimer = null;
    // Per-widget save batching (DD-05): configure-form Save and toolbar
    // bulk-edit fire one notification per affected widget; this Map
    // (instance_id → DOM el) collapses simultaneous notifications into
    // a single bulk POST so the toolbar's N-declarer commit lands as
    // one round-trip.
    this._widgetSaveTimer = null;
    this._pendingWidgetSaves = new Map();
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
   * bulk-edits go through `_scheduleWidgetSave()` instead — they
   * touch a single widget's config and must not commit any staged
   * layout edits during an open edit-mode transaction.
   *
   * In edit mode the change stays client-side until the user clicks
   * the Save button (→ _commitEdit) or the Discard button (→
   * _discardEdit). In view mode the change goes through the same
   * 50ms-debounced whole-blob save path as before.
   */
  _stageOrSave() {
    if (this.mode === 'edit') {
      this._layoutDirty = true;
      return;
    }
    this._scheduleSave();
  }

  /**
   * DD-05 per-widget POST. Configure-form Save and toolbar bulk-edit
   * each fire one notification per affected widget; we collapse
   * simultaneous notifications into a single bulk POST via a 50ms
   * debounce so the toolbar's N-declarer commit lands as one
   * round-trip and so a rapid sequence of configure-form saves
   * coalesces.
   *
   * Only the affected widgets' `config` is patched server-side; the
   * rest of the saved blob (other widgets' positions and configs) is
   * left untouched. This is what makes edit-mode staging safe: a
   * configure-form Save during edit mode no longer commits the staged
   * drag/resize/remove edits.
   */
  _scheduleWidgetSave(widgetEl) {
    if (!this.widgetSaveUrl) {
      // Older index.ctp without the per-widget URL — fall back to the
      // whole-blob path so behaviour stays correct (the leak it
      // re-introduces is documented as a known limitation in those
      // legacy templates).
      this._scheduleSave();
      return;
    }
    const id = widgetEl.getAttribute(ATTR_WIDGET_INSTANCE);
    if (!id) return;
    this._pendingWidgetSaves.set(id, widgetEl);
    if (this._widgetSaveTimer) clearTimeout(this._widgetSaveTimer);
    this._widgetSaveTimer = setTimeout(() => this._flushWidgetSaves(), 50);
  }

  async _flushWidgetSaves() {
    this._widgetSaveTimer = null;
    if (!this._pendingWidgetSaves.size) return true;
    const pending = [...this._pendingWidgetSaves.values()];
    this._pendingWidgetSaves.clear();
    const patches = [];
    for (const el of pending) {
      const instance_id = el.getAttribute(ATTR_WIDGET_INSTANCE);
      if (!instance_id) continue;
      let config = {};
      try {
        config = JSON.parse(el.getAttribute(ATTR_WIDGET_CONFIG) || '{}');
      } catch (_) { /* keep empty */ }
      patches.push({ instance_id, config });
    }
    if (!patches.length) return true;
    try {
      const body = new URLSearchParams({ patches: JSON.stringify(patches) });
      const resp = await fetch(this.widgetSaveUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body,
        credentials: 'same-origin',
      });
      if (resp.status === 404) {
        // No saved blob yet (first-time user) or unknown instance_id
        // (likely concurrent removal). Fall back to a whole-blob save
        // so the user's work isn't lost; this is the unusual path,
        // not the steady-state.
        return await this._saveLayout();
      }
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      this._dispatchEvent('saved', { count: patches.length, perWidget: true });
      return true;
    } catch (err) {
      console.warn('[misp-dashboard] per-widget save failed', err);
      this._dispatchEvent('save-failed', { error: String(err) });
      return false;
    }
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
        // Per-widget POST per DD-05 — the bulk-edit changes only the
        // affected widgets' configs; layout stays untouched. Batched
        // via _scheduleWidgetSave so an N-declarer commit collapses
        // to a single round-trip.
        this._scheduleWidgetSave(widgetEl);
      },
    });

    // Placement listener for the Add Widget flow. _startDraftWidget
    // fires `misp-board:add-widget-pending` on the board root when
    // the user clicks Save in the draft configure form; the listener
    // here resolves the draft into a real tile (fetch wrapper HTML,
    // pick a free slot, addTile, render, persist). Kept event-driven
    // (rather than a direct callback) so theme JS / future
    // extensions can listen too without forking the board module.
    this.root.addEventListener('misp-board:add-widget-pending', (e) => {
      this._placeDraftWidget(e.detail.draftEl, e.detail.meta).catch((err) => {
        console.warn('[misp-dashboard] add-widget placement failed', err);
        this._dispatchEvent('add-widget-failed', { error: String(err) });
      });
    });
  }

  // ---- mode ----

  setMode(mode) {
    if (mode !== 'view' && mode !== 'edit') return;
    if (this.mode === mode) return;
    const prevMode = this.mode;
    this.mode = mode;
    this.root.setAttribute(ATTR_BOARD_MODE, mode);
    // Mirror to <body> so the header (a sibling of the board root,
    // not an ancestor) can target mode-aware CSS rules like the
    // Save / Discard button visibility.
    if (this.root.ownerDocument && this.root.ownerDocument.body) {
      this.root.ownerDocument.body.setAttribute(ATTR_BOARD_MODE, mode);
    }
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
          // Edit-mode UI hides this toggle (CSS:
          // .misp-dashboard-modecontrols-view); Save / Discard
          // buttons are the explicit affordances per DD-05's
          // edit-mode-is-a-transaction. Defensive branch: if a
          // keyboard / devtools / a11y path lands here while dirty,
          // route through Discard (which has its own confirm) so
          // staged work isn't silently dropped.
          if (this.mode === 'edit' && this._layoutDirty) {
            this._discardEdit();
          } else {
            this.setMode(this.mode === 'view' ? 'edit' : 'view');
          }
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
          e.preventDefault();
          // Open the v2 widget gallery inside the configure side
          // panel. On card pick, hand off to _startDraftWidget,
          // which constructs a detached draft DOM node and asks
          // the configure module to render its schema-driven form
          // in the same panel (mode flips from gallery → form).
          openGallery({ onPick: (meta) => this._startDraftWidget(meta) });
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
          //               from "(mixed)" with its peers), and POST a
          //               per-widget config patch to /dashboards/
          //               updateWidgetSettings so any staged layout
          //               edits (edit-mode drag/resize/remove) stay
          //               staged — DD-05 atomicity.
          //   onPreview - live-preview tick (debounced 250ms per
          //               DD-06). data-widget-config already updated;
          //               re-render the body without persisting.
          openConfigure(widgetEl, {
            onSave: (savedEl) => {
              this._renderWidget(savedEl);
              refreshToolbar(this.root);
              this._scheduleWidgetSave(savedEl);
            },
            onPreview: (previewEl) => {
              this._renderWidget(previewEl);
            },
          });
          break;
      }
    });
  }

  // ---- draft widget (Add Widget flow, PRD §5.4 / §5.7) ----

  /**
   * Construct a detached draft widget DOM node carrying the picked
   * widget's metadata (name, schema, placeholder, default size,
   * render kind) and hand it off to the configure module's
   * existing form-render path. On Save, the new config is committed
   * to the draft's `data-widget-config` and a `misp-board:add-
   * widget-pending` event fires with the draft node + meta — the
   * next sub-task (placement) listens for this event and inserts
   * the draft into the grid via `Grid.addTile()` at the next free
   * auto-place slot, then re-renders the widget body. On Cancel,
   * the panel closes through the configure module's existing close
   * chain and the draft node is GC-released (no caller retains it).
   *
   * The draft node is a plain <div> rather than the full wrapper.ctp
   * markup — only the data-widget-* attributes the configure form
   * reads are needed; the wrapper element will be the one cloned
   * onto the grid by the placement task (or created from scratch by
   * a server-side renderWidget call, depending on the placement
   * design). Until then the draft is invisible to the user.
   */
  _startDraftWidget(meta) {
    const panel = document.querySelector('[data-misp-configure-root]');
    // Flip panel mode from "gallery" back to "form" so the
    // configure footer (Save / Cancel) is visible again. The
    // gallery's MutationObserver still owns the close-time cleanup
    // (gallery state release on panel hide), so flipping the mode
    // attribute mid-session is safe.
    if (panel) panel.setAttribute('data-misp-configure-mode', 'form');

    const draft = document.createElement('div');
    draft.setAttribute(ATTR_WIDGET, '');
    draft.setAttribute(ATTR_WIDGET_NAME, meta.widget || '');
    draft.setAttribute(ATTR_WIDGET_INSTANCE, this._mintDraftInstanceId());
    draft.setAttribute(ATTR_WIDGET_CONFIG, '{}');
    // openConfigure JSON.parses these on read; serialise even when
    // empty so the form-render path doesn't fall back to its
    // defensive empty-object branch.
    draft.setAttribute('data-widget-schema', JSON.stringify(meta.schema || {}));
    draft.setAttribute('data-widget-placeholder',
      typeof meta.placeholder === 'string' ? meta.placeholder : '');
    draft.setAttribute('data-position-w', String(meta.width || 1));
    draft.setAttribute('data-position-h', String(meta.height || 1));
    draft.setAttribute('data-widget-render', meta.render || '');

    openConfigure(draft, {
      onSave: (savedDraft) => {
        // Placement is the next sub-task — for now, fire an event
        // that downstream listeners (or the next-task placement
        // handler) can hook. Close the panel via the configure
        // module's own commit() → closeConfigure() path (already
        // invoked before this callback fires per
        // configure.module.mjs line 460 — see commit()).
        this._dispatchEvent('add-widget-pending', {
          draftEl: savedDraft,
          meta,
        });
      },
      onPreview: (previewEl) => {
        // The configure module dispatches the preview tick against
        // the preview proxy (a detached wrapper-shaped node mounted
        // in the panel's preview pane), so `previewEl` is the
        // proxy, not the draft. _renderWidget reads the proxy's
        // attributes and writes the body HTML into the proxy's
        // [data-misp-widget-content] — exactly the same path the
        // Edit Widget flow uses.
        this._renderWidget(previewEl);
      },
    });

    // openConfigure sets the title to "Configure <className>". For
    // a draft, "Add <Title>" reads more naturally; override after
    // the call so the configure module's existing title-write isn't
    // touched (additive-only — see PRD §13 binding decisions).
    const titleEl = document.querySelector('[data-misp-configure-title]');
    if (titleEl && meta.title) titleEl.textContent = `Add ${meta.title}`;
  }

  /**
   * Mint a unique draft-only instance ID. Format distinguishes it
   * from server-minted `w_<N>` IDs so any code path that branches
   * on the ID shape (LayoutFixup write-time mint, the placement
   * task's "is this a draft?" check) can recognise drafts cleanly.
   * The placement task replaces the draft ID with a final
   * `w_<N>`-shaped ID before persisting.
   */
  _mintDraftInstanceId() {
    return `w_draft_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
  }

  /**
   * Mint a `w_<N>` instance ID one past the highest currently in
   * use on this board. Format mirrors LayoutFixup's server-side
   * mint so the persisted layout looks identical regardless of
   * which side stamped the ID. Draft IDs (`w_draft_*`) are
   * deliberately excluded from the max scan so a draft mid-flight
   * doesn't push the next mint up.
   */
  _mintFinalInstanceId() {
    let maxN = 0;
    for (const el of this.root.querySelectorAll(`[${ATTR_WIDGET_INSTANCE}]`)) {
      const id = el.getAttribute(ATTR_WIDGET_INSTANCE) || '';
      const m = /^w_(\d+)$/.exec(id);
      if (m) {
        const n = parseInt(m[1], 10);
        if (Number.isFinite(n) && n > maxN) maxN = n;
      }
    }
    return `w_${maxN + 1}`;
  }

  /**
   * Find the next free auto-place slot for a `w × h` footprint.
   * Scans rows top-down, columns left-to-right, returns the first
   * (x, y) at which a `w × h` rectangle does not overlap any
   * existing tile. Always succeeds — when no slot fits within the
   * currently-occupied rows, places below the lowest existing tile
   * at column 0. The richer push-down-on-collision cascade is
   * parked as Phase 5 work; first-free-slot is the documented
   * Phase 2 contract.
   */
  _findFreeSlot(w, h) {
    if (!this.grid) return { x: 0, y: 0 };
    const cols = this.grid.cols;
    const footprint = Math.min(Math.max(1, w | 0), cols);
    const height    = Math.max(1, h | 0);
    const tiles = this.grid.serialize();
    const maxY = tiles.reduce((m, t) => Math.max(m, t.y + t.h), 0);
    for (let y = 0; y <= maxY; y++) {
      for (let x = 0; x + footprint <= cols; x++) {
        const overlaps = tiles.some((t) =>
          x < t.x + t.w && x + footprint > t.x &&
          y < t.y + t.h && y + height > t.y,
        );
        if (!overlaps) return { x, y };
      }
    }
    return { x: 0, y: maxY };
  }

  /**
   * Apply PRD F5.6.4 inheritance: for every schema entry on the
   * draft whose `type` is a canonical type for which the toolbar
   * currently shows a non-mixed value, write that value into
   * `config[schemaKey]` — but only if the user hasn't already set
   * an explicit value through the draft form. Mutates the passed
   * config object and returns it (for chaining).
   *
   * The "user already set" check is conservative: any defined,
   * non-empty value counts as "user-set" and is left alone. This
   * matches the intuition that a user who scrolled past the field
   * has implicitly accepted whatever the form default is, while a
   * user who actually typed wants their value preserved.
   */
  _applyToolbarInheritance(config, schema) {
    const toolbarValues = currentToolbarValues(this.root);
    const inheritKeys = Object.keys(toolbarValues);
    if (inheritKeys.length === 0) return config;
    for (const [schemaKey, entry] of Object.entries(schema || {})) {
      if (!entry || typeof entry !== 'object') continue;
      const canonicalKey = entry.type;
      if (!Object.prototype.hasOwnProperty.call(toolbarValues, canonicalKey)) continue;
      const existing = config[schemaKey];
      if (existing !== undefined && existing !== null && existing !== '') continue;
      config[schemaKey] = toolbarValues[canonicalKey];
    }
    return config;
  }

  /**
   * Placement orchestrator. Listens for `misp-board:add-widget-
   * pending`; resolves a draft node into a real tile placed on the
   * grid.
   *
   * Sequence:
   *   1. Read draft state (name, config, footprint) and the draft's
   *      schema for inheritance lookup.
   *   2. Apply F5.6.4 toolbar inheritance to the config.
   *   3. Mint a final `w_<N>` instance ID.
   *   4. Find the next free auto-place slot.
   *   5. POST `/dashboards/renderWrapper` to get the theme-resolved
   *      wrapper element (including all §8.5 hooks).
   *   6. Parse the response, snap inline data-* state back onto the
   *      parsed element (the server already emits these, but if
   *      inheritance changed the config after the wrapper was
   *      composed we want the latest values).
   *   7. `Grid.addTile()` at the chosen slot.
   *   8. Kick off `_renderWidget()` to fill the body.
   *   9. Refresh the toolbar (new declarers may have changed
   *      chip state — e.g., a previously-empty toolbar with no
   *      `time_window` declarer now shows one).
   *  10. `_stageOrSave()` so edit-mode commits / view-mode saves
   *      pick up the addition. The edit-mode snapshot does not
   *      contain the new tile, so `_discardEdit` naturally removes
   *      it on Discard.
   *  11. Refresh debug readout.
   */
  async _placeDraftWidget(draftEl, meta) {
    if (!this.wrapperUrl) {
      throw new Error('wrapper-url not configured on board root');
    }
    if (!this.grid) {
      throw new Error('grid not initialised');
    }
    const widgetName = draftEl.getAttribute(ATTR_WIDGET_NAME);
    if (!widgetName) {
      throw new Error('draft missing widget name');
    }
    let config = {};
    try {
      config = JSON.parse(draftEl.getAttribute(ATTR_WIDGET_CONFIG) || '{}');
      if (!config || typeof config !== 'object' || Array.isArray(config)) config = {};
    } catch (_) {
      config = {};
    }
    let schema = {};
    try {
      schema = JSON.parse(draftEl.getAttribute('data-widget-schema') || '{}');
      if (!schema || typeof schema !== 'object' || Array.isArray(schema)) schema = {};
    } catch (_) {
      schema = {};
    }

    this._applyToolbarInheritance(config, schema);

    const w = parseInt(draftEl.getAttribute('data-position-w'), 10) || meta.width  || 4;
    const h = parseInt(draftEl.getAttribute('data-position-h'), 10) || meta.height || 3;
    const instanceId = this._mintFinalInstanceId();
    const { x, y } = this._findFreeSlot(w, h);

    const body = new URLSearchParams({
      widget: widgetName,
      config: JSON.stringify(config),
      w: String(w), h: String(h), x: String(x), y: String(y),
    });
    const resp = await fetch(
      `${this.wrapperUrl}/${encodeURIComponent(instanceId)}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'text/html',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body,
        credentials: 'same-origin',
      },
    );
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const html = (await resp.text()).trim();

    const parsed = new DOMParser().parseFromString(html, 'text/html');
    const wrapperEl = parsed.body.firstElementChild;
    if (!wrapperEl || !wrapperEl.hasAttribute(ATTR_WIDGET)) {
      throw new Error('wrapper response did not contain a widget element');
    }
    // The server emitted the inherited config server-side, but pin
    // it again here so any future code path that mutates config
    // between fetch and placement (none today; insurance) reflects
    // the post-inheritance state on the placed tile.
    wrapperEl.setAttribute(ATTR_WIDGET_CONFIG, JSON.stringify(config));

    this.grid.addTile({ id: instanceId, x, y, w, h, el: wrapperEl });
    this._renderWidget(wrapperEl);
    refreshToolbar(this.root);
    this._stageOrSave();
    this._updateDebugReadout();
    this._dispatchEvent('add-widget-placed', {
      instanceId, widgetName, x, y, w, h,
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
