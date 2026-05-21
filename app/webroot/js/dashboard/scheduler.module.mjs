// SchedulerModule.
//
// Single board-level refresh scheduler (PRD Phase 5; §10 limits). Replaces
// the v1 setTimeout-per-widget cascade with one ticking loop that walks
// every enqueued tile each second, fires renders when their declared
// `data-widget-refresh-delay` has elapsed since the last render, and caps
// concurrent in-flight renders at 4 (PRD §10).
//
// Self-contained: the scheduler does not call /dashboards/renderWidget
// itself. It invokes a `renderFn(widgetEl)` callback supplied at
// construction time, then learns the actual completion timestamp by
// listening for the `misp-board:widget-rendered` event the board already
// dispatches. This indirection means the manual refresh button (which
// calls Board._renderWidget directly) implicitly resets the timer for the
// tile it refreshed — no separate code path.
//
// Public surface (kept minimal — add methods when an actual consumer
// surfaces):
//
//   const s = new Scheduler({ boardRoot, renderFn });
//   s.start();                       // begin ticking + hook Page Visibility
//   s.stop();                        // halt; release listeners
//   s.enqueueWidget(widgetEl);       // register a tile (re-reads delay attr)
//   s.unenqueueWidget(widgetEl);     // drop a tile (e.g. on remove)
//   s.pause();                       // user-controlled pause
//   s.resume();                      // user-controlled resume
//
// Page Visibility behaviour:
//   document.hidden true → scheduler ticks but does not enqueue renders
//                          (low cost — state check only). Visibility
//                          flag is treated as "soft pause".
//   On re-show, do NOT flush overdue renders — that would cause a
//   refresh storm proportional to the away-duration. The tick loop
//   resumes normally; tiles that became overdue while hidden will fire
//   on the next tick at most.

const ATTR_WIDGET           = 'data-misp-widget';
const ATTR_WIDGET_INSTANCE  = 'data-widget-instance-id';
const ATTR_WIDGET_DELAY     = 'data-widget-refresh-delay';

const TICK_MS         = 1000;   // state-check cadence; cheap by design
const INFLIGHT_CAP    = 4;      // PRD §10 concurrent-render limit per board

export class Scheduler {
  /**
   * @param {Object}   opts
   * @param {Element}  opts.boardRoot  the board root element (event target +
   *                                   ownership scope; tiles outside this
   *                                   root are ignored even if enqueued)
   * @param {Function} opts.renderFn   (widgetEl) → void|Promise — invoked
   *                                   when a tile is due. Scheduler does
   *                                   not await; completion is learned via
   *                                   the `misp-board:widget-rendered`
   *                                   event the board dispatches.
   */
  constructor({ boardRoot, renderFn }) {
    if (!boardRoot) throw new Error('Scheduler: boardRoot required');
    if (typeof renderFn !== 'function') {
      throw new Error('Scheduler: renderFn required');
    }
    this.boardRoot = boardRoot;
    this.renderFn = renderFn;

    // instanceId → { el, delayMs, lastRenderAt, inFlight }
    this._tiles = new Map();
    this._tickHandle = null;
    this._inFlightCount = 0;
    this._paused = false;        // user pause (toolbar toggle, future)
    this._docHidden = false;     // Page Visibility soft-pause

    // Bound listeners so stop() can detach the same references.
    this._onRenderedBound = this._onRendered.bind(this);
    this._onVisibilityBound = this._onVisibility.bind(this);
  }

  // ---- lifecycle ----

  start() {
    if (this._tickHandle) return;
    this._docHidden = typeof document !== 'undefined' && document.hidden === true;
    this.boardRoot.addEventListener('misp-board:widget-rendered', this._onRenderedBound);
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', this._onVisibilityBound);
    }
    this._tickHandle = setInterval(() => this._tick(), TICK_MS);
  }

  stop() {
    if (this._tickHandle) {
      clearInterval(this._tickHandle);
      this._tickHandle = null;
    }
    this.boardRoot.removeEventListener('misp-board:widget-rendered', this._onRenderedBound);
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this._onVisibilityBound);
    }
    this._tiles.clear();
    this._inFlightCount = 0;
  }

  // ---- tile registry ----

  /**
   * Register (or refresh the registration of) a tile. Re-reading the
   * delay attribute every call means configure-save can re-enqueue a
   * tile after a per-instance refresh override changes (PRD F2.5,
   * future sub-task) without the scheduler caching a stale value.
   *
   * A tile with no `data-widget-refresh-delay` attribute, or a non-
   * positive value, is silently ignored — the absence of the attribute
   * is the canonical "no auto-refresh" signal.
   */
  enqueueWidget(widgetEl) {
    if (!widgetEl || !widgetEl.getAttribute) return;
    if (!this.boardRoot.contains(widgetEl)) return;
    const id = widgetEl.getAttribute(ATTR_WIDGET_INSTANCE);
    if (!id) return;
    const raw = widgetEl.getAttribute(ATTR_WIDGET_DELAY);
    const delaySec = parseInt(raw || '0', 10);
    if (!Number.isFinite(delaySec) || delaySec <= 0) {
      // Tile was previously enqueued but now declares no refresh —
      // drop it so the tick loop doesn't keep iterating an inert entry.
      this._tiles.delete(id);
      return;
    }
    // Preserve lastRenderAt across re-enqueues so a configure-save
    // doesn't accidentally reset the timer.
    const existing = this._tiles.get(id);
    this._tiles.set(id, {
      el: widgetEl,
      delayMs: delaySec * 1000,
      lastRenderAt: existing ? existing.lastRenderAt : Date.now(),
      inFlight: existing ? existing.inFlight : false,
    });
  }

  unenqueueWidget(widgetEl) {
    if (!widgetEl || !widgetEl.getAttribute) return;
    const id = widgetEl.getAttribute(ATTR_WIDGET_INSTANCE);
    if (!id) return;
    const entry = this._tiles.get(id);
    if (entry && entry.inFlight) this._inFlightCount--;
    this._tiles.delete(id);
  }

  // ---- pause ----

  pause()  { this._paused = true;  }
  resume() { this._paused = false; }

  // ---- internals ----

  _tick() {
    if (this._paused || this._docHidden) return;
    if (this._inFlightCount >= INFLIGHT_CAP) return;
    const now = Date.now();
    // FIFO over Map insertion order. A tile that joined later waits
    // behind earlier ones when both come due in the same tick —
    // matches Map iteration semantics and is good enough for a
    // dashboard's scale (PRD §10 default cap = 24 tiles per board).
    for (const [, entry] of this._tiles) {
      if (this._inFlightCount >= INFLIGHT_CAP) break;
      if (entry.inFlight) continue;
      if ((now - entry.lastRenderAt) < entry.delayMs) continue;
      // Defensive: a tile DOM-removed without unenqueueWidget would
      // sit here forever. Detached elements aren't in the board's
      // DOM tree; skip + drop.
      if (!this.boardRoot.contains(entry.el)) {
        this._tiles.delete(entry.el.getAttribute(ATTR_WIDGET_INSTANCE));
        continue;
      }
      entry.inFlight = true;
      this._inFlightCount++;
      try {
        this.renderFn(entry.el);
      } catch (err) {
        // renderFn shouldn't throw synchronously, but if it does,
        // free the slot so the queue doesn't stall.
        entry.inFlight = false;
        this._inFlightCount--;
        console.warn('[misp-dashboard:scheduler] render dispatch threw', err);
      }
    }
  }

  _onRendered(e) {
    const id = e && e.detail && e.detail.instanceId;
    if (!id) return;
    const entry = this._tiles.get(id);
    if (!entry) return;
    if (entry.inFlight) {
      entry.inFlight = false;
      this._inFlightCount = Math.max(0, this._inFlightCount - 1);
    }
    entry.lastRenderAt = Date.now();
  }

  _onVisibility() {
    if (typeof document === 'undefined') return;
    this._docHidden = document.hidden === true;
    // No flush on re-show — the next normal tick handles overdue tiles.
  }
}
