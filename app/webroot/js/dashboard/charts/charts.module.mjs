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
import { geoNaturalEarth1, geoRobinson, geoCylindricalEqualArea } from './vendor/d3-geo.bundle.mjs';
import { registerMispTheme, MISP_THEME_NAME } from './echarts-theme.mjs';
import { initMonitorChart } from './monitor-chart.mjs';

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
  // hard-coded a 12-stop palette; we ship a simpler 2-stop gradient.
  // A widget picks a named palette via payload.palette (DD-13) — each
  // maps to a semantic token pair [low, high] so a retoned/dark theme
  // still recolours it; unknown names fall back to 'accent'. The 3rd/4th
  // entries are the hard fallbacks if the token is undefined.
  const PALETTES = {
    accent:  ['--misp-dash-accent-muted',  '--misp-dash-accent-hover', 'rgba(37,99,235,0.10)', '#1d4ed8'],
    danger:  ['--misp-dash-danger-muted',  '--misp-dash-danger',       'rgba(220,38,38,0.12)', '#dc2626'],
    success: ['--misp-dash-success-muted', '--misp-dash-success',      'rgba(22,163,74,0.12)', '#16a34a'],
    warning: ['--misp-dash-warning-muted', '--misp-dash-warning',      'rgba(217,119,6,0.12)', '#d97706'],
    info:    ['--misp-dash-info-muted',    '--misp-dash-info',         'rgba(8,145,178,0.12)', '#0891b2'],
  };
  const pal = PALETTES[payload.palette] || PALETTES.accent;
  const rampLow      = tokenOn(hostEl, pal[0], pal[2]);
  const rampHigh     = tokenOn(hostEl, pal[1], pal[3]);
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

  // Map projection. Default 'naturalEarth' (rounded, area-faithful-ish,
  // less polar distortion — DD-17, superseding DD-14's mercator default)
  // when payload.projection is unset; 'equirectangular' omits the
  // projection so ECharts plots raw lon/lat (its native flat grid).
  // Mercator + equirectangular are dependency-free (DD-14); 'naturalEarth',
  // 'robinson' and 'peters' are vendored d3-geo projections (DD-15, DD-16).
  // Unknown names fall back to the default (naturalEarth).
  const wrapD3 = (p) => ({ project: (pt) => p(pt), unproject: (pt) => p.invert(pt) });
  const PROJECTIONS = {
    mercator: {
      // Standard spherical Mercator. Unlike ECharts' native lon/lat
      // path (which it auto-flips for screen), a CUSTOM projection's
      // output is used as raw canvas coordinates — y increases DOWNWARD.
      // So `project` negates the y term to put north at the top, and
      // `unproject` inverts that with exp(-y) to stay an exact inverse
      // (round-trip verified). Both signs must match: a positive-log
      // forward round-trips fine but renders the map upside down.
      // Latitude is clamped to the Web-Mercator limit so Antarctica's
      // -90° vertices don't send y to infinity.
      project: function (pt) {
        var lat = Math.max(-85.0511, Math.min(85.0511, pt[1]));
        return [pt[0] / 180 * Math.PI, -Math.log(Math.tan((Math.PI / 2 + lat / 180 * Math.PI) / 2))];
      },
      unproject: function (c) {
        return [c[0] * 180 / Math.PI, 2 * 180 / Math.PI * Math.atan(Math.exp(-c[1])) - 90];
      },
    },
    // Robinson + Natural Earth (DD-15) and Gall-Peters (DD-16) via
    // vendored d3-geo. d3 bakes north-up into its y-down output, so —
    // unlike the hand-rolled mercator above — no sign handling is needed;
    // project/unproject map straight onto the d3 projection + its .invert
    // (both round-trip exact). Instances are stateless for project/invert.
    // 'peters' is the Gall-Peters cylindrical equal-area projection with
    // standard parallels at +/-45 deg (geoCylindricalEqualArea.parallel(45)).
    naturalEarth: wrapD3(geoNaturalEarth1()),
    robinson: wrapD3(geoRobinson()),
    peters: wrapD3(geoCylindricalEqualArea().parallel(45)),
  };
  const projName = payload.projection || 'naturalEarth';
  // 'equirectangular' (or any name without a function) => no projection,
  // i.e. ECharts' native flat lon/lat rendering.
  const projection = PROJECTIONS[projName] || (projName === 'equirectangular' ? null : PROJECTIONS.naturalEarth);

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
      ...(projection ? { projection } : {}),
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

// ---- pie (used/free donut) ----

// Human-readable byte size for pie tooltips. Binary units (KiB-style
// powers of 1024) since this serves disk/memory monitors.
function formatBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let size = v / 1024;
  let i = 0;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return `${size.toFixed(1)} ${units[i]}`;
}

function buildPieOption(payload, hostEl) {
  const slices = payload.slices || {};
  const colours = payload.colours || {};
  const labels = Object.keys(slices);

  const text  = tokenOn(hostEl, '--misp-dash-text',        '#1d2025');
  const muted = tokenOn(hostEl, '--misp-dash-text-muted',  '#5b6573');
  const accent = tokenOn(hostEl, '--misp-dash-accent',     '#1d4ed8');
  const danger = tokenOn(hostEl, '--misp-dash-danger',     '#dc2626');
  const border = tokenOn(hostEl, '--misp-dash-border',     '#d8dde4');

  // Threshold styling: when used_pct exceeds threshold, the conventional
  // "Used" slice turns red. Drives off the same data the SimpleList
  // system widget thresholds on, but expressed via theme tokens.
  const overThreshold =
    payload.threshold != null && payload.used_pct != null &&
    Number(payload.used_pct) > Number(payload.threshold);
  const sliceColour = (label) => {
    if (colours[label]) return colours[label];
    if (label === 'Used') return overThreshold ? danger : accent;
    if (label === 'Free') return border;
    return undefined;
  };

  const data = labels.map((label) => {
    const item = { name: label, value: Number(slices[label]) || 0 };
    const c = sliceColour(label);
    if (c) item.itemStyle = { color: c };
    return item;
  });

  return {
    // Centre read-out of the headline percentage (when supplied).
    ...(payload.used_pct != null ? {
      title: {
        text: `${payload.used_pct}%`,
        subtext: 'used',
        left: 'center',
        top: '34%',
        textStyle: { color: overThreshold ? danger : text, fontSize: 20 },
        subtextStyle: { color: muted, fontSize: 11 },
      },
    } : {}),
    tooltip: {
      trigger: 'item',
      formatter: (p) => `${p.name}: ${formatBytes(p.value)} (${p.percent}%)`,
    },
    legend: { bottom: 0, textStyle: { color: text } },
    series: [{
      type: 'pie',
      radius: ['48%', '72%'],
      center: ['50%', '44%'],
      avoidLabelOverlap: true,
      label: { show: false },
      labelLine: { show: false },
      data,
    }],
  };
}

const builders = {
  bar: buildBarOption,
  line: buildLineOption,
  geo: buildGeoOption,
  pie: buildPieOption,
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
  let payload = {};
  try {
    payload = JSON.parse(el.getAttribute(ATTR_CHART_PAYLOAD) || '{}');
  } catch (err) {
    console.warn(`[misp-dashboard] malformed chart payload`, err);
  }

  // Streaming monitor charts (CPU/memory) manage their own polling and
  // lifecycle — they have no static builder. initMonitorChart returns a
  // handle whose teardown() disposeChart() calls (clears the interval).
  if (kind === 'monitor') {
    liveCharts.set(el, initMonitorChart(el, payload));
    return;
  }

  const builder = builders[kind];
  if (!builder) {
    console.warn(`[misp-dashboard] unknown chart kind "${kind}"`);
    return;
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
  // Monitor charts carry a teardown() that also clears their poll
  // interval + visibility wiring; static charts just need disconnect +
  // dispose.
  if (typeof live.teardown === 'function') {
    live.teardown();
  } else {
    live.observer.disconnect();
    live.chart.dispose();
  }
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
