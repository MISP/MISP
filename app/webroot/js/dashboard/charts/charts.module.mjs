// Dashboard chart bootstrap.
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
  const drilldown = payload.drilldown || {};
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
      const label = orderedLabels[i];
      const color = colours[label];
      const drillable = !!drilldown[label];
      if (!color && !drillable) return v;
      const item = { value: v };
      if (color) item.itemStyle = { color };
      // Cursor hint communicates clickability to the user; the actual
      // click is wired centrally in initChart() below.
      if (drillable) item.cursor = 'pointer';
      return item;
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
  const drilldown = payload.drilldown || {};
  const seriesData = Object.entries(data).map(([name, value]) => {
    const item = { name, value: Number(value) || 0 };
    if (drilldown[name]) item.cursor = 'pointer';
    return item;
  });
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

// ---- line (multi-series) ----

function buildLineOption(payload, hostEl) {
  const rows = Array.isArray(payload.data) ? payload.data : [];
  const colours = payload.colours || {};
  const drilldown = payload.drilldown || {};
  const yAxisLabel = payload.yAxis || 'Count';

  const dates = rows.map((r) => String(r.date ?? ''));
  // Collect every non-date key across all rows so a tag that only
  // appears late still gets a series with leading zeros.
  const seen = new Set();
  const lineKeys = [];
  for (const r of rows) {
    for (const k of Object.keys(r)) {
      if (k !== 'date' && !seen.has(k)) {
        seen.add(k);
        lineKeys.push(k);
      }
    }
  }

  // Truncate the legend text so long tag names (e.g. taxonomies like
  // `misp-galaxy:threat-actor="..."`) don't crowd out the chart.
  const text = tokenOn(hostEl, '--misp-dash-text', '#1d2025');
  const muted = tokenOn(hostEl, '--misp-dash-text-muted', '#5b6573');

  const series = lineKeys.map((k) => {
    const data = rows.map((r) => Number(r[k]) || 0);
    const colour = colours[k];
    const drillable = !!drilldown[k];
    return {
      name: k,
      type: 'line',
      data,
      // Only show point markers when the series is sparse enough to
      // read them; dense series read better as continuous lines.
      showSymbol: data.length <= 20,
      smooth: false,
      emphasis: { focus: 'series' },
      ...(colour ? { itemStyle: { color: colour }, lineStyle: { color: colour } } : {}),
      ...(drillable ? { cursor: 'pointer' } : {}),
    };
  });

  return {
    grid: { left: 8, right: 16, top: 36, bottom: 24, containLabel: true },
    tooltip: { trigger: 'axis' },
    legend: {
      type: 'scroll',
      top: 0,
      textStyle: { color: text },
      formatter: (name) => (name.length > 28 ? name.slice(0, 27) + '…' : name),
    },
    xAxis: {
      type: 'category',
      data: dates,
      boundaryGap: false,
      axisLabel: { color: muted },
    },
    yAxis: {
      type: 'value',
      name: yAxisLabel,
      nameTextStyle: { color: muted },
      axisLabel: { color: muted },
    },
    series,
  };
}

const builders = {
  bar: buildBarOption,
  line: buildLineOption,
  geo: buildGeoOption,
};

// ---- public API ----

// Pick the drilldown lookup key from an ECharts click params object,
// based on chart kind. Bar/geo key on the category/region name;
// line keys on the series name (clicking any point of a line resolves
// to the series). Returns null when the click isn't on a data datum
// the drilldown convention covers.
function pickDrilldownKey(kind, params) {
  if (!params) return null;
  switch (kind) {
    case 'bar':  return params.name || null;
    case 'line': return params.seriesName || null;
    case 'geo':  return params.name || null;
    default:     return null;
  }
}

// Navigate to a DD-03 drilldown URL. Modifier-click (ctrl/cmd/shift)
// and middle-click open in a new tab per PRD F2.6; plain click
// navigates the current window.
function followDrilldown(url, params) {
  const ev = params && params.event && params.event.event;
  const newTab = ev && (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button === 1);
  if (newTab) {
    window.open(url, '_blank', 'noopener,noreferrer');
  } else {
    window.location.href = url;
  }
}

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

  // DD-03 per-datum drilldown: when the payload carries a `drilldown`
  // map, wire a click listener that looks up the URL by the clicked
  // datum's lookup key. URL safety was gated server-side by
  // DashboardURLValidator before serialisation, so the client trusts
  // every URL it sees here.
  const drilldown = (payload && payload.drilldown) || {};
  if (Object.keys(drilldown).length > 0) {
    chart.on('click', (params) => {
      const key = pickDrilldownKey(kind, params);
      const url = key ? drilldown[key] : null;
      if (url) followDrilldown(url, params);
    });
  }

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
