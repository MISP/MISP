// RefreshIndicatorModule.
//
// "Updated Ns ago" chip on each widget tile that has auto-refresh
// active. Listens for the existing `misp-board:widget-rendered`
// event the board dispatches on every successful render, stores
// per-instance timestamps, and ticks a single 1s setInterval that
// re-formats every visible chip using Intl.RelativeTimeFormat
// (style: 'narrow', numeric: 'auto'; locale = navigator.language).
//
// **Auto-refresh gating (PRD §F3.x):** the chip is hidden on tiles
// that have no active auto-refresh — i.e., the shared `resolveDelaySec`
// (exported from scheduler.module.mjs) returns 0. Two cases:
//   - widget class declares no $autoRefreshDelay (most widgets)
//   - widget class declares N but config['refresh_delay']=0 overrides
//     (per-instance disable via F2.5)
// The chip carries weight only when there's an expectation of
// freshness; on a static tile, "updated 4m ago" is just clutter.
//
// Why a separate module (not folded into Scheduler):
//   - The scheduler's job is "decide when to enqueue renders";
//     mixing in "format chip text" muddles the responsibility.
//   - Both modules listen to the same event independently; no
//     ordering / race concerns.
//   - Shared resolution helper is the single source of truth —
//     both modules import resolveDelaySec from scheduler.module.mjs.
//
// On a `widget-error` event, the timestamp is NOT updated — the chip
// continues to show the elapsed time since the last *successful*
// render. This matches the user-facing meaning ("how stale is the
// data?") rather than the technical meaning ("when did we last
// try?"). A widget stuck in error state shows an ever-growing chip,
// which is exactly the diagnostic signal you want.
//
// Lifecycle: no explicit register/unregister API. The tick body
// querySelectorAll's every `data-misp-widget-refresh-indicator`
// element currently inside the board root; removed tiles drop out
// naturally because their DOM is gone. The Map<instanceId,
// timestamp> may retain orphan entries after a tile removal —
// memory cost is one Date.now() per session-removed tile, bounded
// by user edits, not pruned aggressively for v1.

import { resolveDelaySec } from './scheduler.module.mjs';

const ATTR_WIDGET_INSTANCE  = 'data-widget-instance-id';
const ATTR_INDICATOR        = 'data-misp-widget-refresh-indicator';

const TICK_MS = 1000;

// Bucket cutoffs for the formatter. Order matters: scanned top-down.
const BUCKETS = [
  { unit: 'second', divisor: 1,     maxSeconds: 60 },
  { unit: 'minute', divisor: 60,    maxSeconds: 3600 },
  { unit: 'hour',   divisor: 3600,  maxSeconds: 86400 },
  { unit: 'day',    divisor: 86400, maxSeconds: Infinity },
];

export class RefreshIndicator {
  /**
   * @param {Object}  opts
   * @param {Element} opts.boardRoot  the board root element — event source
   *                                  and DOM scope; indicator spans
   *                                  outside this root are ignored.
   * @param {string}  [opts.locale]   override locale; defaults to
   *                                  navigator.language ?? 'en'.
   */
  constructor({ boardRoot, locale }) {
    if (!boardRoot) throw new Error('RefreshIndicator: boardRoot required');
    this.boardRoot = boardRoot;
    const loc = locale
      || (typeof navigator !== 'undefined' && navigator.language)
      || 'en';
    // 'narrow' renders "5s ago" / "1m ago" / "2h ago" in en-US; other
    // locales emit their conventional compact form via CLDR data
    // bundled with the JS engine. `numeric: 'auto'` substitutes "now"
    // / "yesterday" / "tomorrow" where applicable instead of "0s ago".
    this._rtf = new Intl.RelativeTimeFormat(loc, {
      numeric: 'auto',
      style: 'narrow',
    });

    // instanceId → epoch-ms timestamp of last successful render
    this._timestamps = new Map();
    this._tickHandle = null;
    this._docHidden = false;

    this._onRenderedBound = this._onRendered.bind(this);
    this._onVisibilityBound = this._onVisibility.bind(this);
  }

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
    this._timestamps.clear();
  }

  // ---- internals ----

  _onRendered(e) {
    const id = e && e.detail && e.detail.instanceId;
    if (!id) return;
    this._timestamps.set(id, Date.now());
  }

  _onVisibility() {
    if (typeof document === 'undefined') return;
    this._docHidden = document.hidden === true;
  }

  _tick() {
    if (this._docHidden) return;
    const now = Date.now();
    const indicators = this.boardRoot.querySelectorAll(`[${ATTR_INDICATOR}]`);
    for (const span of indicators) {
      // The indicator lives inside the widget tile; walk up to find
      // the instance id rather than re-rooting the querySelectorAll.
      const tile = span.closest(`[${ATTR_WIDGET_INSTANCE}]`);
      if (!tile) continue;
      const id = tile.getAttribute(ATTR_WIDGET_INSTANCE);
      if (!id) continue;
      // Auto-refresh gating: tiles with resolved delay 0 (no class
      // default, or explicit `refresh_delay: 0` override) get no
      // chip — the freshness signal is meaningless on static data.
      // Re-checked every tick so a configure-save override change
      // (e.g. setting refresh_delay to 0 mid-session) takes effect
      // on the next tick.
      if (resolveDelaySec(tile) <= 0) {
        if (span.textContent !== '') span.textContent = '';
        continue;
      }
      const ts = this._timestamps.get(id);
      if (ts === undefined) {
        // First render hasn't fired yet; leave the chip empty.
        if (span.textContent !== '') span.textContent = '';
        continue;
      }
      const elapsedSec = Math.max(0, Math.floor((now - ts) / 1000));
      const text = this._formatElapsed(elapsedSec);
      if (span.textContent !== text) span.textContent = text;
    }
  }

  _formatElapsed(elapsedSec) {
    for (const b of BUCKETS) {
      if (elapsedSec < b.maxSeconds) {
        const value = Math.floor(elapsedSec / b.divisor);
        return this._rtf.format(-value, b.unit);
      }
    }
    // Unreachable: BUCKETS' last entry has maxSeconds: Infinity.
    return '';
  }
}
