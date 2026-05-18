// dashboard-v2 GridModule — Phase 0.2 prototype.
// Drag, snap, collision, resize on a 12-column CSS Grid layout.
// Drag is wired via Pragmatic Drag and Drop (PDD); resize uses raw
// pointer events. The module is dependency-free at runtime apart
// from the vendored PDD bundle.
//
// Usage:
//   import { Grid } from '/js/dashboard/grid/grid.module.mjs';
//   const g = new Grid(rootEl, { cols: 12, rowHeight: 80, gap: 8 });
//   g.addTile({ id: 't1', x: 0, y: 0, w: 4, h: 3, el: someDiv });
//   ...
//   g.serialize() => [{id, x, y, w, h}, ...]

import {
  draggable,
  monitorForElements,
  combine,
} from './vendor/pragmatic-drag-and-drop.bundle.mjs';

const DRAG_TYPE = 'misp-dashboard-tile';

export class Grid {
  constructor(rootEl, opts = {}) {
    this.root = rootEl;
    this.cols = opts.cols ?? 12;
    this.rowHeight = opts.rowHeight ?? 80;
    this.gap = opts.gap ?? 8;
    // opts.onCommit (optional): invoked from _commit() whenever a
    // drag-drop or resize-end produces an actual change to any tile's
    // x/y/w/h. Used by BoardModule to schedule a persistence save.
    // No-op commits (e.g. a tile dropped back at its original cell)
    // do not fire the callback.
    this.onCommit = opts.onCommit ?? null;
    this.tiles = new Map(); // id -> tile
    this.cleanups = [];
    this.dragState = null;
    this.resizeState = null;

    this.root.classList.add('dgrid-root');
    this.root.style.display = 'grid';
    this.root.style.gridTemplateColumns = `repeat(${this.cols}, 1fr)`;
    this.root.style.gridAutoRows = `${this.rowHeight}px`;
    this.root.style.gap = `${this.gap}px`;
    this.root.style.position = 'relative';

    // Global ghost element used during drag.
    this.ghost = document.createElement('div');
    this.ghost.className = 'dgrid-ghost';
    this.ghost.style.cssText =
      'position:absolute;pointer-events:none;border:2px dashed #5aa9ff;' +
      'background:rgba(90,169,255,0.12);border-radius:4px;display:none;' +
      'z-index:10;transition:left .05s,top .05s,width .05s,height .05s;';
    this.root.appendChild(this.ghost);

    // Global drag monitor (one per grid).
    this.cleanups.push(
      monitorForElements({
        canMonitor: ({ source }) => source.data.type === DRAG_TYPE,
        onDragStart: ({ source, location }) => this._onDragStart(source, location),
        onDrag:      ({ source, location }) => this._onDrag(source, location),
        onDrop:      ({ source, location }) => this._onDrop(source, location),
      }),
    );
  }

  // ---- public API ----

  addTile(tile) {
    if (this.tiles.has(tile.id)) throw new Error(`tile id ${tile.id} already present`);
    if (this._collides(tile.x, tile.y, tile.w, tile.h, tile.id)) {
      throw new Error(`tile ${tile.id} overlaps existing tiles`);
    }
    this.tiles.set(tile.id, tile);
    this._applyTileStyle(tile);
    tile.el.dataset.tileId = tile.id;
    this.root.appendChild(tile.el);
    this._attachDrag(tile);
    this._attachResize(tile);
  }

  removeTile(id) {
    const t = this.tiles.get(id);
    if (!t) return;
    t.el.remove();
    this.tiles.delete(id);
  }

  serialize() {
    return [...this.tiles.values()].map(({ id, x, y, w, h }) => ({ id, x, y, w, h }));
  }

  destroy() {
    this.cleanups.forEach(fn => fn());
    this.cleanups = [];
    this.ghost.remove();
  }

  // ---- internal: layout math ----

  _applyTileStyle(t) {
    t.el.style.gridColumn = `${t.x + 1} / span ${t.w}`;
    t.el.style.gridRow    = `${t.y + 1} / span ${t.h}`;
    t.el.style.position   = 'relative';
  }

  _cellSize() {
    const totalGap = this.gap * (this.cols - 1);
    const rect = this.root.getBoundingClientRect();
    // The grid root may carry CSS padding (.misp-dashboard-main has
    // 16px/24px). getBoundingClientRect() includes that padding, but
    // CSS Grid lays columns out across the content box, and an
    // absolutely-positioned child's `left: 0` resolves to the padding
    // box's outer edge (= rect.left with no border). Both `pointerToCell`
    // and `showGhost` need the padding to translate between page coords
    // and column coords correctly.
    const cs = getComputedStyle(this.root);
    const padL = parseFloat(cs.paddingLeft) || 0;
    const padR = parseFloat(cs.paddingRight) || 0;
    const padT = parseFloat(cs.paddingTop) || 0;
    const cellW = (rect.width - padL - padR - totalGap) / this.cols;
    return { cellW, cellH: this.rowHeight, rect, padL, padT };
  }

  _pointerToCell(clientX, clientY) {
    const { cellW, cellH, rect, padL, padT } = this._cellSize();
    const localX = clientX - rect.left - padL;
    const localY = clientY - rect.top  - padT;
    // Round to nearest cell, including the gaps as part of the cell width.
    const x = Math.max(0, Math.min(this.cols - 1,
      Math.floor(localX / (cellW + this.gap))));
    const y = Math.max(0,
      Math.floor(localY / (cellH + this.gap)));
    return { x, y };
  }

  _collides(x, y, w, h, exceptId = null) {
    if (x < 0 || x + w > this.cols || y < 0) return true;
    for (const t of this.tiles.values()) {
      if (t.id === exceptId) continue;
      if (x < t.x + t.w && x + w > t.x && y < t.y + t.h && y + h > t.y) return true;
    }
    return false;
  }

  // Cascade: when a tile is moved/resized into space occupied by others,
  // push the displaced tiles downward in column order until they fit.
  _resolveCascade(movedId, x, y, w, h) {
    const proposed = new Map(this.tiles);
    proposed.set(movedId, { ...proposed.get(movedId), x, y, w, h });

    let stable = false, guard = 0;
    while (!stable && guard++ < 50) {
      stable = true;
      const moving = proposed.get(movedId);
      for (const [id, t] of proposed) {
        if (id === movedId) continue;
        const overlap =
          moving.x < t.x + t.w && moving.x + moving.w > t.x &&
          moving.y < t.y + t.h && moving.y + moving.h > t.y;
        if (overlap) {
          const newY = moving.y + moving.h;
          // Also push any tile already below this one, recursively.
          const pushed = { ...t, y: newY };
          proposed.set(id, pushed);
          stable = false;
        }
      }
      // Repeat displacement check with each newly pushed tile as `moving`.
      for (const [id, t] of proposed) {
        if (id === movedId) continue;
        for (const [id2, t2] of proposed) {
          if (id === id2) continue;
          const overlap =
            t.x < t2.x + t2.w && t.x + t.w > t2.x &&
            t.y < t2.y + t2.h && t.y + t.h > t2.y;
          if (overlap && t2.y >= t.y) {
            proposed.set(id2, { ...t2, y: t.y + t.h });
            stable = false;
          }
        }
      }
    }
    return proposed;
  }

  _commit(layout) {
    let changed = false;
    for (const [id, t] of layout) {
      const cur = this.tiles.get(id);
      if (cur.x !== t.x || cur.y !== t.y || cur.w !== t.w || cur.h !== t.h) {
        cur.x = t.x; cur.y = t.y; cur.w = t.w; cur.h = t.h;
        this._applyTileStyle(cur);
        changed = true;
      }
    }
    if (changed && this.onCommit) {
      this.onCommit();
    }
  }

  // ---- internal: drag (PDD-driven) ----

  _attachDrag(tile) {
    const handle = tile.el.querySelector('[data-drag-handle]') ?? tile.el;
    const cleanup = draggable({
      element: handle,
      // Drag is gated by the board's edit mode (read off the board
      // root's data-misp-board-mode attribute, which the BoardModule
      // toggles). PDD calls canDrag at gesture-start, so flipping the
      // attribute mid-page takes effect immediately without a re-bind.
      canDrag: () => this.root.getAttribute('data-misp-board-mode') === 'edit',
      getInitialData: () => ({ type: DRAG_TYPE, tileId: tile.id }),
    });
    this.cleanups.push(cleanup);
  }

  _onDragStart(source) {
    const id = source.data.tileId;
    const t = this.tiles.get(id);
    if (!t) return;
    this.dragState = { id, originX: t.x, originY: t.y };
    t.el.classList.add('dgrid-dragging');
  }

  _onDrag(source, location) {
    if (!this.dragState) return;
    const { x, y } = this._pointerToCell(
      location.current.input.clientX,
      location.current.input.clientY,
    );
    const t = this.tiles.get(this.dragState.id);
    const valid = !this._collides(x, y, t.w, t.h, t.id);
    this._showGhost(x, y, t.w, t.h, valid);
  }

  _onDrop(source, location) {
    if (!this.dragState) return;
    const t = this.tiles.get(this.dragState.id);
    t.el.classList.remove('dgrid-dragging');
    this.ghost.style.display = 'none';
    if (!location.current.input) { this.dragState = null; return; }
    const { x, y } = this._pointerToCell(
      location.current.input.clientX,
      location.current.input.clientY,
    );
    if (!this._collides(x, y, t.w, t.h, t.id)) {
      const cascaded = this._resolveCascade(t.id, x, y, t.w, t.h);
      this._commit(cascaded);
    }
    this.dragState = null;
  }

  _showGhost(x, y, w, h, valid) {
    const { cellW, cellH, padL, padT } = this._cellSize();
    // ghost is position:absolute inside the root, so left/top resolve
    // to the padding-box outer edge — add the root's padding so the
    // ghost aligns with where CSS Grid actually places column 1 / row 1.
    this.ghost.style.left = `${padL + x * (cellW + this.gap)}px`;
    this.ghost.style.top  = `${padT + y * (cellH + this.gap)}px`;
    this.ghost.style.width  = `${w * cellW + (w - 1) * this.gap}px`;
    this.ghost.style.height = `${h * cellH + (h - 1) * this.gap}px`;
    this.ghost.style.borderColor = valid ? '#5aa9ff' : '#ff6b6b';
    this.ghost.style.background  = valid
      ? 'rgba(90,169,255,0.12)' : 'rgba(255,107,107,0.12)';
    this.ghost.style.display = 'block';
  }

  // ---- internal: resize (raw pointer events) ----

  _attachResize(tile) {
    const handle = tile.el.querySelector('[data-resize-handle]');
    if (!handle) return;
    const onDown = (e) => this._onResizeStart(tile, e);
    handle.addEventListener('pointerdown', onDown);
    this.cleanups.push(() => handle.removeEventListener('pointerdown', onDown));
  }

  _onResizeStart(tile, e) {
    e.preventDefault();
    e.stopPropagation();
    const handle = e.currentTarget;
    handle.setPointerCapture(e.pointerId);
    this.resizeState = { id: tile.id, handle, pointerId: e.pointerId };
    const onMove = (ev) => this._onResizeMove(ev);
    const onUp   = (ev) => this._onResizeEnd(ev, onMove, onUp);
    handle.addEventListener('pointermove', onMove);
    handle.addEventListener('pointerup', onUp);
    handle.addEventListener('pointercancel', onUp);
    tile.el.classList.add('dgrid-resizing');
  }

  _onResizeMove(e) {
    if (!this.resizeState) return;
    const t = this.tiles.get(this.resizeState.id);
    const { x, y } = this._pointerToCell(e.clientX, e.clientY);
    const newW = Math.max(1, x - t.x + 1);
    const newH = Math.max(1, y - t.y + 1);
    const valid = !this._collides(t.x, t.y, newW, newH, t.id);
    this._showGhost(t.x, t.y, newW, newH, valid);
  }

  _onResizeEnd(e, onMove, onUp) {
    const handle = this.resizeState?.handle;
    if (!handle) return;
    handle.removeEventListener('pointermove', onMove);
    handle.removeEventListener('pointerup', onUp);
    handle.removeEventListener('pointercancel', onUp);
    handle.releasePointerCapture(this.resizeState.pointerId);
    const t = this.tiles.get(this.resizeState.id);
    t.el.classList.remove('dgrid-resizing');
    this.ghost.style.display = 'none';
    const { x, y } = this._pointerToCell(e.clientX, e.clientY);
    const newW = Math.max(1, x - t.x + 1);
    const newH = Math.max(1, y - t.y + 1);
    if (!this._collides(t.x, t.y, newW, newH, t.id)) {
      const cascaded = this._resolveCascade(t.id, t.x, t.y, newW, newH);
      this._commit(cascaded);
    }
    this.resizeState = null;
  }
}
