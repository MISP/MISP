// Streaming line chart for the live system-monitor widgets (CPU / memory).
//
// Unlike the static chart kinds (bar/line/geo), which render a fixed
// dataset once per server render, a monitor chart polls its OWN widget
// handler every `interval_sec` and appends each sample to a rolling
// buffer capped at `window_sec`, accumulating a time series CLIENT-SIDE
// while the dashboard is open. The buffer lives only in this closure, so
// a page reload — or a manual refresh, which disposes the tile — starts
// fresh (matching the user's "recording entries while the dashboard is
// open").
//
// It reuses the existing renderWidget `exportjson` contract (the same
// call Board._exportWidget makes) to fetch a fresh handler() payload as
// JSON — no dedicated endpoint, route, or ACL. The widget declares
// autoRefreshDelay=false so the board scheduler never re-renders (and
// thereby disposes) the tile; this module's own interval is the sole
// driver.
//
// Bootstrapped from charts.module.mjs initChart() for kind "monitor".
// initMonitorChart() returns a handle { chart, observer, teardown };
// disposeChart() calls teardown so the interval + listeners don't leak
// when the tile is removed or manually refreshed.

import echarts from './vendor/echarts.bundle.mjs';
import { MISP_THEME_NAME } from './echarts-theme.mjs';

const ATTR_WIDGET          = 'data-misp-widget';
const ATTR_WIDGET_NAME     = 'data-widget-name';
const ATTR_WIDGET_INSTANCE = 'data-widget-instance-id';
const ATTR_WIDGET_CONFIG   = 'data-widget-config';
// Same board-root attribute Board reads as its renderWidget base URL
// (index.ctp `data-misp-board-renderwidget-url`). Reusing it keeps a
// single source of truth and avoids a baseurl dependency in the .ctp.
const ATTR_RENDER_URL      = 'data-misp-board-renderwidget-url';

const MIN_INTERVAL_SEC = 2;

function tokenOn(el, name, fallback) {
  const v = getComputedStyle(el).getPropertyValue(name).trim();
  return v || fallback;
}

function hhmmss(d) {
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function isFiniteNum(v) {
  return v !== null && v !== undefined && Number.isFinite(Number(v));
}

function baseOption(payload, hostEl) {
  const accent = tokenOn(hostEl, '--misp-dash-accent',     '#1d4ed8');
  const muted  = tokenOn(hostEl, '--misp-dash-text-muted', '#5b6573');
  const unit = payload.unit || '';
  // yMax acts as a FLOOR for the axis ceiling: the axis is always at
  // least [0 .. yMax], but expands if a sample exceeds it (CPU load
  // normalized to %-of-cores can exceed 100 on an overloaded host;
  // memory used-% never does). null → fully auto-scaled.
  const yFloorMax = isFiniteNum(payload.yMax) ? Number(payload.yMax) : null;

  return {
    grid: { left: 8, right: 14, top: 24, bottom: 22, containLabel: true },
    tooltip: {
      trigger: 'axis',
      formatter: (ps) => {
        const p = Array.isArray(ps) ? ps[0] : ps;
        return `${p.axisValue}<br/>${p.seriesName}: ${p.data}${unit}`;
      },
    },
    xAxis: {
      type: 'category',
      data: [],
      boundaryGap: false,
      axisLabel: { color: muted, hideOverlap: true },
    },
    yAxis: {
      type: 'value',
      min: 0,
      ...(yFloorMax != null
        ? { max: (v) => Math.max(yFloorMax, Math.ceil(v.max || 0)) }
        : {}),
      axisLabel: { color: muted, formatter: `{value}${unit}` },
    },
    series: [{
      name: payload.label || 'value',
      type: 'line',
      data: [],
      showSymbol: false,
      smooth: true,
      areaStyle: { opacity: 0.12 },
      lineStyle: { color: accent, width: 2 },
      itemStyle: { color: accent },
    }],
  };
}

/**
 * Create + start a streaming monitor chart on `el`. `payload` carries the
 * initial sample + presentation/polling params (value, label, unit, yMax,
 * window_sec, interval_sec). Returns a handle whose teardown() stops the
 * poll loop and disposes the chart.
 */
export function initMonitorChart(el, payload) {
  const chart = echarts.init(el, MISP_THEME_NAME, { renderer: 'canvas' });
  chart.setOption(baseOption(payload, el));

  const tile      = el.closest(`[${ATTR_WIDGET}]`);
  const rootEl    = el.closest(`[${ATTR_RENDER_URL}]`);
  const widget    = tile ? tile.getAttribute(ATTR_WIDGET_NAME) : null;
  const instance  = tile ? tile.getAttribute(ATTR_WIDGET_INSTANCE) : null;
  const config    = tile ? (tile.getAttribute(ATTR_WIDGET_CONFIG) || '{}') : '{}';
  const renderUrl = rootEl ? rootEl.getAttribute(ATTR_RENDER_URL) : null;

  const intervalSec = Math.max(MIN_INTERVAL_SEC, Number(payload.interval_sec) || 10);
  const pollUrl     = (renderUrl && instance)
    ? `${renderUrl}/${encodeURIComponent(instance)}/exportjson:1`
    : null;

  // Draw a server-persisted series (DD-30): [[ts, value], ...], oldest
  // first. The buffer + windowing live server-side (Redis), so the client
  // just repaints whatever history the handler returns — in place (no
  // flicker), and consistent across reload / refresh / multiple viewers.
  // Timestamps are the server's, so labels are stable across reloads.
  function render(history) {
    const times = [];
    const values = [];
    for (const row of (Array.isArray(history) ? history : [])) {
      if (!Array.isArray(row) || row.length < 2) continue;
      times.push(hhmmss(new Date(Number(row[0]) * 1000)));
      values.push(Number(row[1]));
    }
    chart.setOption({ xAxis: { data: times }, series: [{ data: values }] });
  }

  // Seed from the history the server render already returned, so the chart
  // shows the accumulated series immediately (not just one fresh point).
  render(payload.history);

  let stopped = false;
  async function poll() {
    if (stopped || !pollUrl || !widget) return;
    // Soft-pause while the tab is hidden (matches the board scheduler's
    // Page-Visibility behaviour). Leaves a time gap rather than polling
    // a backgrounded tab; resumes on the next tick when shown.
    if (typeof document !== 'undefined' && document.hidden) return;
    try {
      const body = new URLSearchParams({ widget, config });
      const resp = await fetch(pollUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
          'X-CSRF-Token': (window.csrfToken || ''),
        },
        body,
        credentials: 'same-origin',
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      if (data && Array.isArray(data.history)) render(data.history);
    } catch (err) {
      // Non-fatal: skip this tick, keep the accumulated series.
      console.warn('[misp-dashboard:monitor] poll failed', err);
    }
  }

  const timer = setInterval(poll, intervalSec * 1000);

  const observer = new ResizeObserver(() => chart.resize());
  observer.observe(el);

  function teardown() {
    stopped = true;
    clearInterval(timer);
    observer.disconnect();
    chart.dispose();
  }

  return { chart, observer, teardown };
}
