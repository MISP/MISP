// dashboard-v2 — chart bootstrap.
//
// Scans rendered widget content for chart containers (the `.ctp`
// renderers emit static `<div data-misp-chart="<kind>"
// data-misp-chart-payload="<json>">` tags), instantiates ECharts on
// each, and wires a per-container ResizeObserver so the chart resizes
// when the GridModule changes tile dimensions.
//
// Why a separate scan rather than scripts inside the renderer output:
// the BoardModule injects renderer HTML via `target.innerHTML = html`,
// and inline `<script>` tags created that way do not execute. Static
// markup + a post-render scan is the simplest pattern that works.

import echarts from './vendor/echarts.bundle.mjs';
import { registerMispTheme, MISP_THEME_NAME } from './echarts-theme.mjs';

const ATTR_CHART         = 'data-misp-chart';
const ATTR_CHART_PAYLOAD = 'data-misp-chart-payload';

// Per-container handle used for resize / dispose. Keyed weakly so a
// detached container can be GC'd without an explicit cleanup call.
const liveCharts = new WeakMap();

// ---- option builders (one per chart kind) ----

function buildBarOption(payload) {
  const data = payload.data || {};
  const colours = payload.colours || {};
  const labels = Object.keys(data);
  const values = labels.map((k) => Number(data[k]) || 0);

  // Render largest at top, matching v1 BarChart's visual ordering
  // (v1 renderer iterates the already-sorted-desc dict from the widget
  // and stacks rows top-down). ECharts category axis on the y-axis
  // reverses by default, so we reverse the input arrays once here.
  const orderedLabels = labels.slice().reverse();
  const orderedValues = values.slice().reverse();

  const series = [{
    type: 'bar',
    data: orderedValues.map((v, i) => {
      const color = colours[orderedLabels[i]];
      return color ? { value: v, itemStyle: { color } } : v;
    }),
    label: { show: true, position: 'right' },
  }];

  return {
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: { type: 'value' },
    yAxis: {
      type: 'category',
      data: orderedLabels,
      axisLabel: { width: 160, overflow: 'truncate' },
    },
    series,
  };
}

// ---- geo (world map) ----

let worldMapPromise = null;

/**
 * Lazy-load + register the vendored world GeoJSON. First call kicks
 * off the fetch; subsequent calls await the same promise so the file
 * is only downloaded once per page load. Registration happens after
 * the JSON is parsed.
 */
function ensureWorldMap() {
  if (worldMapPromise) return worldMapPromise;
  const url = new URL('./vendor/world-110m.geojson', import.meta.url);
  worldMapPromise = fetch(url.href, { credentials: 'same-origin' })
    .then((r) => {
      if (!r.ok) throw new Error(`world-110m.geojson HTTP ${r.status}`);
      return r.json();
    })
    .then((geo) => {
      echarts.registerMap('world', geo);
      return true;
    });
  return worldMapPromise;
}

/**
 * Read a CSS custom property, trim, fall back to the supplied default.
 * Resolved against the chart container so a wrapper class redefining
 * tokens for an embedded mini-dashboard would be honoured.
 */
function tokenOn(el, name, fallback) {
  const v = getComputedStyle(el).getPropertyValue(name).trim();
  return v || fallback;
}

function buildGeoOption(payload, hostEl) {
  const data = payload.data || {};
  const scope = payload.scope || '';
  const seriesData = Object.entries(data).map(([name, value]) => ({
    name,
    value: Number(value) || 0,
  }));
  const values = seriesData.map((d) => d.value);
  const maxV = values.length ? Math.max(...values) : 1;

  // Drive the colour ramp from CSS tokens so a Level 1 theme (PRD §8.1)
  // retones the map without writing JS. The v1 jvectormap renderer
  // hard-coded a 12-stop palette; we ship a simpler 2-stop gradient
  // anchored on the accent token, which themes already redefine.
  const rampLow      = tokenOn(hostEl, '--misp-dash-accent-muted', 'rgba(37,99,235,0.10)');
  const rampHigh     = tokenOn(hostEl, '--misp-dash-accent-hover', '#1d4ed8');
  const text         = tokenOn(hostEl, '--misp-dash-text',         '#1d2025');
  // Country fill: `border` is mid-gray in light + slightly lighter
  // than surface-raised in dark, giving consistent visibility in both
  // themes. Previously used `surface` (page-bg) which is always darker
  // than the widget body → invisible non-active countries on dark.
  // Country outline: `border-strong` is one step further from fill in
  // both directions (darker than fill in light, lighter in dark) so
  // the country edges read.
  const countryFill   = tokenOn(hostEl, '--misp-dash-border',        '#d8dde4');
  const countryStroke = tokenOn(hostEl, '--misp-dash-border-strong', '#b6bdc7');

  return {
    tooltip: {
      trigger: 'item',
      formatter: (p) => {
        // Countries with no data show value=undefined; keep the tooltip
        // minimal in that case so the map is still browsable.
        const v = p.data && typeof p.data.value === 'number' ? p.data.value : null;
        if (v === null) return p.name;
        return `${p.name}<br/>${scope}: ${v}`;
      },
    },
    visualMap: {
      type: 'continuous',
      min: 0,
      max: maxV || 1,
      left: 6,
      bottom: 6,
      orient: 'vertical',
      calculable: false,
      itemWidth: 8,
      itemHeight: 80,
      textStyle: { fontSize: 10, color: text },
      inRange: { color: [rampLow, rampHigh] },
    },
    series: [{
      type: 'map',
      map: 'world',
      roam: true,
      itemStyle: {
        areaColor: countryFill,
        borderColor: countryStroke,
        borderWidth: 0.4,
      },
      emphasis: {
        label: { show: false },
        itemStyle: { areaColor: rampHigh },
      },
      select: { disabled: true },
      data: seriesData,
    }],
  };
}

const builders = {
  bar: buildBarOption,
  geo: buildGeoOption,
};

// ---- public API ----

/**
 * Initialise a single chart container. Async so geo charts can wait
 * for the world-map registration; bar charts resolve synchronously.
 * Idempotent: a live chart on the same element is disposed first.
 */
async function initChart(el) {
  if (liveCharts.has(el)) disposeChart(el);
  const kind = el.getAttribute(ATTR_CHART);
  const builder = builders[kind];
  if (!builder) {
    console.warn(`[misp-dashboard] unknown chart kind "${kind}"`);
    return;
  }
  let payload = {};
  try {
    payload = JSON.parse(el.getAttribute(ATTR_CHART_PAYLOAD) || '{}');
  } catch (err) {
    console.warn(`[misp-dashboard] malformed chart payload`, err);
  }
  if (kind === 'geo') {
    await ensureWorldMap();
  }
  const chart = echarts.init(el, MISP_THEME_NAME, { renderer: 'canvas' });
  chart.setOption(builder(payload, el));

  const observer = new ResizeObserver(() => chart.resize());
  observer.observe(el);
  liveCharts.set(el, { chart, observer });
}

/**
 * Initialise every chart container found inside `containerEl`. Returns
 * a promise that resolves once every chart has been created — callers
 * may await it (e.g. tests) or fire-and-forget (BoardModule). Idempotent.
 */
export function initChartsIn(containerEl) {
  if (!containerEl) return Promise.resolve();
  registerMispTheme();
  const els = [...containerEl.querySelectorAll(`[${ATTR_CHART}]`)];
  return Promise.all(els.map(initChart));
}

/** Dispose a single chart container (no-op if not live). */
export function disposeChart(el) {
  const live = liveCharts.get(el);
  if (!live) return;
  live.observer.disconnect();
  live.chart.dispose();
  liveCharts.delete(el);
}

/** Dispose every chart inside `containerEl`. Call before innerHTML
 * replacement and before grid.removeTile so ECharts instances and
 * their window/document listeners do not leak.
 */
export function disposeChartsIn(containerEl) {
  if (!containerEl) return;
  const els = containerEl.querySelectorAll(`[${ATTR_CHART}]`);
  for (const el of els) disposeChart(el);
}
