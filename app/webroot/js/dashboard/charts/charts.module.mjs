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
import { geoNaturalEarth1, geoRobinson, geoCylindricalEqualArea, geoOrthographic } from './vendor/d3-geo.bundle.mjs';
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

/**
 * Network/hub-and-spoke graph (kind "network", render kind NetworkGraph).
 *
 * Payload:
 *   {
 *     nodes: [
 *       { id, name, url, status: 'self'|'ok'|'warn'|'error', message },
 *       ...                       // the 'self' node (or nodes[0]) is the hub
 *     ],
 *     links: [ { source: <id>, target: <id> }, ... ],
 *     error: 'message'            // optional empty-state (handled in the .ctp)
 *   }
 *
 * Layout is fixed (layout:'none'): the hub sits at the centre and the
 * remaining nodes are placed on a ring around it, so node positions are
 * deterministic and don't reshuffle on each auto-refresh (unlike a force
 * layout). Status maps to semantic theme tokens, so themes retone it.
 * The tooltip shows each node's name, URL and test outcome — where an
 * admin reads the reason for an outage.
 */
// A server/rack glyph filled in `colour`, as an ECharts `image://` symbol
// (a 2-unit rack with white LEDs + vent bars). Built from the resolved
// theme-token colour at render time, so node colours stay theme-aware.
function serverSymbol(colour) {
  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' +
    `<rect x="3.5" y="3.5" width="17" height="7" rx="1.8" fill="${colour}"/>` +
    `<rect x="3.5" y="13.5" width="17" height="7" rx="1.8" fill="${colour}"/>` +
    '<circle cx="7" cy="7" r="1.15" fill="#fff"/>' +
    '<circle cx="7" cy="17" r="1.15" fill="#fff"/>' +
    '<rect x="10.5" y="6.2" width="7" height="1.6" rx="0.8" fill="#fff" opacity="0.9"/>' +
    '<rect x="10.5" y="16.2" width="7" height="1.6" rx="0.8" fill="#fff" opacity="0.9"/>' +
    '</svg>';
  return 'image://data:image/svg+xml;base64,' + btoa(svg);
}

// A feed/RSS glyph in `colour` (DD-40): two concentric arcs opening to the
// upper-right + a filled dot in the lower-left. Universally-recognised
// "feed" iconography; distinct from serverSymbol() at a glance.
function feedSymbol(colour) {
  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">' +
    `<circle cx="6.5" cy="17.5" r="2.2" fill="${colour}"/>` +
    '<path d="M5 13 A6 6 0 0 1 11 19" fill="none" ' +
    `stroke="${colour}" stroke-width="2.4" stroke-linecap="round"/>` +
    '<path d="M5 7.5 A11.5 11.5 0 0 1 16.5 19" fill="none" ' +
    `stroke="${colour}" stroke-width="2.4" stroke-linecap="round"/>` +
    '</svg>';
  return 'image://data:image/svg+xml;base64,' + btoa(svg);
}

function buildNetworkOption(payload, hostEl) {
  const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
  const links = Array.isArray(payload.links) ? payload.links : [];

  const text   = tokenOn(hostEl, '--misp-dash-text',         '#1d2025');
  const border = tokenOn(hostEl, '--misp-dash-border',       '#d8dde4');
  const statusColour = {
    self:  tokenOn(hostEl, '--misp-dash-accent',  '#2563eb'),
    ok:    tokenOn(hostEl, '--misp-dash-success', '#16a34a'),
    warn:  tokenOn(hostEl, '--misp-dash-warning', '#d97706'),
    error: tokenOn(hostEl, '--misp-dash-danger',  '#dc2626'),
    info:  tokenOn(hostEl, '--misp-dash-info',    '#0891b2'),
  };
  // 2 kinds × 5 statuses = 10 cached symbols (DD-40). Hub is always
  // a server-rack — the hub *is* a MISP instance, regardless of
  // whether the spokes around it are servers or feeds.
  const symbolFor = {
    server: {
      self:  serverSymbol(statusColour.self),
      ok:    serverSymbol(statusColour.ok),
      warn:  serverSymbol(statusColour.warn),
      error: serverSymbol(statusColour.error),
      info:  serverSymbol(statusColour.info),
    },
    feed: {
      self:  feedSymbol(statusColour.self),
      ok:    feedSymbol(statusColour.ok),
      warn:  feedSymbol(statusColour.warn),
      error: feedSymbol(statusColour.error),
      info:  feedSymbol(statusColour.info),
    },
  };

  // Hub = the 'self' node (fallback: first node). Spokes ring around it.
  const hubIdx = Math.max(0, nodes.findIndex((n) => n.status === 'self'));
  const spokes = nodes.filter((_, i) => i !== hubIdx);
  const R = 100;            // ring radius in the layout's own units
  const pos = new Map();    // node id -> [x, y]
  pos.set(nodes[hubIdx] ? nodes[hubIdx].id : '__hub', [0, 0]);
  spokes.forEach((n, i) => {
    // Start at the top (-90°) and go clockwise; single spoke sits above.
    const a = (-Math.PI / 2) + (2 * Math.PI * i) / Math.max(1, spokes.length);
    pos.set(n.id, [Math.cos(a) * R, Math.sin(a) * R]);
  });

  const data = nodes.map((n, i) => {
    const isHub = i === hubIdx;
    const [x, y] = pos.get(n.id) || [0, 0];
    // Default kind is 'server' — preserves DD-33's MispAdminSyncTestWidget
    // byte-identically (it emits no kind field). Hub overrides to 'server'
    // unconditionally; the diagram centre is always a MISP instance.
    const kind = isHub ? 'server' : (symbolFor[n.kind] ? n.kind : 'server');
    const kindMap = symbolFor[kind];
    return {
      id: String(n.id),
      name: n.name || String(n.id),
      x, y,
      symbol: kindMap[n.status] || kindMap.error,
      symbolSize: isHub ? 44 : 32,
      symbolKeepAspect: true,
      label: { fontWeight: isHub ? 'bold' : 'normal' },
      // custom fields for the tooltip
      _url: n.url || '',
      _message: n.message || '',
    };
  });

  const idIndex = new Map(nodes.map((n, i) => [String(n.id), i]));
  const edges = links
    .map((l) => ({ source: idIndex.get(String(l.source)), target: idIndex.get(String(l.target)) }))
    .filter((e) => e.source != null && e.target != null);

  return {
    tooltip: {
      trigger: 'item',
      formatter: (p) => {
        if (p.dataType !== 'node') return '';
        const d = p.data || {};
        const url = d._url ? `<div>${d._url}</div>` : '';
        const msg = d._message ? `<div>${d._message}</div>` : '';
        return `<b>${p.name}</b>${url}${msg}`;
      },
    },
    series: [{
      type: 'graph',
      layout: 'none',
      roam: true,
      // ECharts fits the node-centre bbox nearly to this rect, so the
      // margins must leave room for the symbol radius + the 'bottom'-
      // positioned labels (roomier bottom + sides) or they clip.
      left: '20%', right: '20%', top: '16%', bottom: '22%',
      label: { show: true, position: 'bottom', color: text, fontSize: 11 },
      edgeLabel: { show: false },
      lineStyle: { color: border, width: 1.5 },
      emphasis: { focus: 'adjacency', lineStyle: { width: 2.5 } },
      data,
      links: edges,
    }],
  };
}

// ---- pew-pew map (DD-45) ----

// Default view centre for the orthographic "globe" mode, as d3's
// [lambda, phi] rotation (the visible centre is [-lambda, -phi]). [10,
// -30] => centre near [-10, 30]: a North-Atlantic framing showing the
// Americas, Europe/Africa, and the Middle East/Asia attacker side
// together, validated in the DD-46 spike. Rotation is static in v1
// (DD-46: auto-rotate deferred to polish).
const PEWPEW_GLOBE_ROTATE = [10, -30];

/**
 * Hemisphere-culling orthographic projection for the pew-pew "globe"
 * mode (DD-46, superseding DD-45's echarts-gl plan). d3's
 * geoOrthographic, called as a point function `p([lon,lat])`, does NOT
 * apply clipAngle — back-hemisphere points fold onto the front face.
 * So we cull explicitly: return [NaN, NaN] for any point whose
 * great-circle angle from the view centre exceeds 90° (cosine < 0).
 * ECharts' `geo` coordinate system tolerates the NaN sentinel — its
 * bounding-box fit ignores NaNs and the canvas renderer skips NaN path
 * segments — so the limb renders clean with no folding (spike-verified).
 * `rotate` is d3's [lambda, phi]; the view centre is [-lambda, -phi].
 */
function orthographicProjection(rotate) {
  const p = geoOrthographic().rotate(rotate);
  const DEG = Math.PI / 180;
  const lon0 = -rotate[0] * DEG;
  const lat0 = -rotate[1] * DEG;
  const sinLat0 = Math.sin(lat0);
  const cosLat0 = Math.cos(lat0);
  return {
    project: (pt) => {
      const lon = pt[0] * DEG;
      const lat = pt[1] * DEG;
      // Cosine of the great-circle angle between the point and the
      // view centre; < 0 means the far (back) hemisphere — cull it.
      const cosc = sinLat0 * Math.sin(lat)
        + cosLat0 * Math.cos(lat) * Math.cos(lon - lon0);
      if (cosc < 0) return [NaN, NaN];
      return p(pt);
    },
    unproject: (xy) => p.invert(xy),
  };
}

/**
 * Animated attacker→victim arcs over a world map (the "pew pew" map).
 * Payload from PewPewMapWidget::handler():
 *   { mode, flows: [{ src:[lon,lat], dst:[lon,lat], value,
 *                     src_iso, dst_iso }] }
 * Centroids are resolved server-side (DD-45 Phase B1) so we just plot
 * raw lon/lat through the `geo` coordinate system.
 *
 * Two modes share one builder (DD-45 single-widget mode switch,
 * dispatch stays SYNC per DD-46):
 *   - `mode !== '3d-globe'` (default '2d'): native equirectangular —
 *     no custom projection, so the arcs read as the classic flat-map
 *     pew-pew.
 *   - `mode === '3d-globe'`: a hemisphere-culling orthographic
 *     projection (DD-46) turns the same `geo` into a from-space "2.5D"
 *     globe (d3-geo `geoOrthographic`, already vendored — no echarts-gl,
 *     no WebGL). Back-hemisphere arcs/countries cull to a clean limb.
 *
 * Three z-stacked layers over the `geo` world map (identical in both
 * modes — only the projection differs):
 *   1. `lines` static arc bodies — per-arc width scales by
 *      log(value), opacity by normalised value; danger token.
 *   2. `lines` animated trail — a moving arrowhead riding each arc
 *      (effect.show), same danger colour, zero-width base line so the
 *      static layer owns the body.
 *   3. `effectScatter` destination glow — a pulsing ripple at each
 *      victim centroid, sized by total incoming value; warning token.
 *
 * Colours resolve via tokenOn() so a retoned/dark theme (PRD §8.1)
 * recolours the arcs and glow without touching JS. Aggregate-only
 * (DD-11/DD-45): no drilldown, no per-arc click handler.
 */
function buildPewPewOption(payload, hostEl) {
  const flows = Array.isArray(payload.flows) ? payload.flows : [];

  const danger  = tokenOn(hostEl, '--misp-dash-danger',        '#dc2626');
  const warning = tokenOn(hostEl, '--misp-dash-warning',       '#d97706');
  const countryFill   = tokenOn(hostEl, '--misp-dash-border',        '#d8dde4');
  const countryStroke = tokenOn(hostEl, '--misp-dash-border-strong', '#b6bdc7');

  const maxV = flows.reduce((m, f) => Math.max(m, Number(f.value) || 0), 0) || 1;
  const logMax = Math.log(maxV + 1) || 1;
  // Arc thickness: 0.6..3.2px on a log scale so a single-event arc is
  // still visible and a high-count arc reads heavier without dominating.
  const widthOf = (v) => 0.6 + 2.6 * (Math.log((Number(v) || 0) + 1) / logMax);
  // Static-body opacity: 0.25..0.85 by normalised value.
  const opacityOf = (v) => 0.25 + 0.6 * ((Number(v) || 0) / maxV);

  const linesData = flows.map((f) => ({
    coords: [f.src, f.dst],
    value: Number(f.value) || 0,
    src_iso: f.src_iso,
    dst_iso: f.dst_iso,
    lineStyle: { width: widthOf(f.value), opacity: opacityOf(f.value) },
  }));

  // Aggregate incoming value per victim centroid for the glow size.
  const dstAgg = {};
  for (const f of flows) {
    const key = f.dst_iso || `${f.dst[0]},${f.dst[1]}`;
    if (!dstAgg[key]) dstAgg[key] = { coord: f.dst, iso: f.dst_iso, value: 0 };
    dstAgg[key].value += Number(f.value) || 0;
  }
  const dstValues = Object.values(dstAgg).map((d) => d.value);
  const maxDst = dstValues.length ? Math.max(...dstValues) : 1;
  const scatterData = Object.values(dstAgg).map((d) => ({
    name: d.iso || '',
    value: [d.coord[0], d.coord[1], d.value],
  }));
  // Glow radius: 4..14px by normalised incoming value.
  const glowSize = (val) => {
    const v = Array.isArray(val) ? val[2] : val;
    return 4 + 10 * ((Number(v) || 0) / maxDst);
  };

  return {
    tooltip: {
      trigger: 'item',
      formatter: (p) => {
        if (p.seriesType === 'lines') {
          const d = p.data || {};
          return `${d.src_iso || '?'} &rarr; ${d.dst_iso || '?'}<br/>${d.value ?? ''}`;
        }
        if (p.seriesType === 'effectScatter') {
          const v = Array.isArray(p.value) ? p.value[2] : '';
          return `${p.name || ''}<br/>${v}`;
        }
        return '';
      },
    },
    geo: {
      map: 'world',
      roam: true,
      silent: true,
      // 'globe' mode (DD-46): swap the projection to a hemisphere-
      // culling orthographic so the same arcs read as a from-space
      // 2.5D globe. '2d' (default) uses ECharts' native flat lon/lat.
      ...(payload.mode === '3d-globe'
        ? { projection: orthographicProjection(PEWPEW_GLOBE_ROTATE) }
        : {}),
      itemStyle: {
        areaColor: countryFill,
        borderColor: countryStroke,
        borderWidth: 0.4,
      },
      emphasis: { disabled: true },
    },
    series: [
      {
        type: 'lines',
        coordinateSystem: 'geo',
        zlevel: 1,
        lineStyle: { color: danger, curveness: 0.2 },
        data: linesData,
      },
      {
        type: 'lines',
        coordinateSystem: 'geo',
        zlevel: 2,
        effect: {
          show: true,
          period: 6,
          trailLength: 0.3,
          symbol: 'arrow',
          symbolSize: 5,
          color: danger,
        },
        // Zero-width base line: only the moving arrowhead shows here;
        // the static layer (zlevel 1) draws the visible arc body.
        lineStyle: { color: danger, width: 0, opacity: 0, curveness: 0.2 },
        data: linesData,
      },
      {
        type: 'effectScatter',
        coordinateSystem: 'geo',
        zlevel: 2,
        rippleEffect: { brushType: 'stroke', scale: 3 },
        symbolSize: glowSize,
        itemStyle: { color: warning },
        data: scatterData,
      },
    ],
  };
}

// ---- pew-pew WebGL globe (DD-47) ----

// Texture skins + lazy bundle are resolved relative to THIS module (the
// same import.meta.url pattern ensureWorldMap uses) so a MISP baseurl
// subpath still works. The skin is chosen per widget instance (DD-49,
// payload.skin); only the selected skin's image is fetched.
const GLOBE_TEXTURES = {
  night: new URL('./vendor/earth-night-2k.jpg', import.meta.url).href,
  day:   new URL('./vendor/earth-day-2k.jpg',   import.meta.url).href,
  dark:  new URL('./vendor/earth-dark-2k.jpg',  import.meta.url).href,
  char:  new URL('./vendor/char.png',           import.meta.url).href, // easter egg (DD-49)
  nacre: new URL('./vendor/planet_nacre.png',   import.meta.url).href, // easter egg (DD-49)
};

// Memoised lazy import so a second webgl-globe widget on the same page
// reuses the first fetch of the heavy (≈508 KB gz) Three.js bundle. The
// bundle is fetched ONLY here — never by the 2d / 3d-globe modes, never
// by the main echarts bundle (DD-47).
let globeBundlePromise = null;
function loadGlobeBundle() {
  if (!globeBundlePromise) {
    globeBundlePromise = import('./vendor/globe.bundle.mjs');
  }
  return globeBundlePromise;
}

// Add an alpha channel to a CSS colour token. Handles #rgb / #rrggbb
// and rgb()/rgba(); anything else is returned solid. The --misp-dash-*
// tokens are hex, so the arc gradient + ring fade resolve correctly; an
// exotic theme value just degrades to a solid colour.
function withAlpha(colour, alpha) {
  const c = (colour || '').trim();
  let m = c.match(/^#([0-9a-f]{3})$/i);
  if (m) {
    const h = m[1];
    const r = parseInt(h[0] + h[0], 16);
    const g = parseInt(h[1] + h[1], 16);
    const b = parseInt(h[2] + h[2], 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  m = c.match(/^#([0-9a-f]{6})$/i);
  if (m) {
    const h = m[1];
    return `rgba(${parseInt(h.slice(0, 2), 16)}, `
      + `${parseInt(h.slice(2, 4), 16)}, `
      + `${parseInt(h.slice(4, 6), 16)}, ${alpha})`;
  }
  m = c.match(/^rgba?\(([^)]+)\)$/i);
  if (m) {
    const [r, g, b] = m[1].split(',').map((s) => s.trim());
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  return c || `rgba(0, 0, 0, ${alpha})`;
}

/**
 * WebGL globe mode (DD-47) — the opt-in "Globe (3D)" pew-pew render.
 * Unlike the 2d / 3d-globe ECharts modes (one buildPewPewOption that
 * returns an option object), globe.gl owns its own WebGL <canvas>, so
 * this is a dedicated init path, NOT a builder. It lazy-imports the
 * heavy globe.bundle.mjs (Three.js) on first use only, maps the shared
 * flows[] payload to globe.gl arcs + pulsing destination rings, and
 * returns a { teardown } handle so disposeChart()'s teardown branch
 * (the same one the monitor charts use) tears it down cleanly.
 *
 * Non-blocking: the handle is returned synchronously and the import
 * resolves in the background behind a loading placeholder, so a board
 * with several widgets doesn't stall its whole init promise on the
 * Three.js download. teardown() flips `disposed` so a dispose that
 * races ahead of a slow import is honoured.
 *
 * Theming is bespoke (DD-47 G6): globe.gl won't read --misp-dash-*, so
 * applyColours() reads the tokens via tokenOn() and a MutationObserver
 * on <html data-theme> re-applies arc / ring / atmosphere colours on
 * light<->dark with no re-init (the zero-JS retheme the ECharts modes
 * get for free is not automatic here).
 */
function initWebglGlobe(hostEl, payload) {
  const flows = Array.isArray(payload.flows) ? payload.flows : [];
  const textureUrl = GLOBE_TEXTURES[payload.skin] || GLOBE_TEXTURES.night;

  // One arc per flow; value drives stroke (log scale). Endpoints are
  // [lon, lat] server-resolved centroids (DD-45 B1).
  const maxV = flows.reduce((m, f) => Math.max(m, Number(f.value) || 0), 0) || 1;
  const logMax = Math.log(maxV + 1) || 1;
  const strokeOf = (v) => 0.3 + 1.1 * (Math.log((Number(v) || 0) + 1) / logMax);
  const arcs = flows.map((f) => ({
    startLat: f.src[1], startLng: f.src[0],
    endLat: f.dst[1], endLng: f.dst[0],
    value: Number(f.value) || 0,
    src_iso: f.src_iso, dst_iso: f.dst_iso,
    stroke: strokeOf(f.value),
  }));

  // One pulsing ring per victim centroid, sized by total incoming value
  // (mirrors the 2d/3d-globe effectScatter glow aggregation).
  const dstAgg = {};
  for (const f of flows) {
    const key = f.dst_iso || `${f.dst[0]},${f.dst[1]}`;
    if (!dstAgg[key]) dstAgg[key] = { lat: f.dst[1], lng: f.dst[0], value: 0 };
    dstAgg[key].value += Number(f.value) || 0;
  }
  const rings = Object.values(dstAgg);
  const maxDst = rings.reduce((m, r) => Math.max(m, r.value), 0) || 1;
  const radiusOf = (v) => 2 + 4 * ((Number(v) || 0) / maxDst);

  // Loading placeholder (self-contained inline style — no CSS dep)
  // while the heavy Three.js bundle downloads.
  const placeholder = (text) =>
    `<div style="display:flex;align-items:center;justify-content:center;`
    + `height:100%;width:100%;color:var(--misp-dash-text-muted,#6b7280);`
    + `font-size:0.9em;">${text}</div>`;
  hostEl.innerHTML = placeholder('Loading 3D globe…');

  let globe = null;
  let resizeObs = null;
  let themeObs = null;
  let disposed = false;

  const applyColours = () => {
    if (!globe) return;
    const danger = tokenOn(hostEl, '--misp-dash-danger', '#dc2626');
    const warning = tokenOn(hostEl, '--misp-dash-warning', '#d97706');
    globe
      .arcColor(() => [withAlpha(danger, 0.15), withAlpha(danger, 0.95)])
      .ringColor(() => (t) => withAlpha(warning, 1 - t))
      .atmosphereColor(danger);
  };

  loadGlobeBundle()
    .then(({ default: Globe }) => {
      if (disposed) return;          // disposed before the import resolved
      hostEl.innerHTML = '';
      globe = Globe()(hostEl)
        .width(hostEl.clientWidth || 600)
        .height(hostEl.clientHeight || 400)
        .backgroundColor('rgba(0, 0, 0, 0)')   // blend with the card
        .globeImageUrl(textureUrl)
        .showAtmosphere(true)
        .atmosphereAltitude(0.18)
        .arcsData(arcs)
        .arcStartLat((d) => d.startLat)
        .arcStartLng((d) => d.startLng)
        .arcEndLat((d) => d.endLat)
        .arcEndLng((d) => d.endLng)
        .arcStroke((d) => d.stroke)
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashInitialGap(() => Math.random())
        .arcDashAnimateTime(1500)
        .ringsData(rings)
        .ringLat((d) => d.lat)
        .ringLng((d) => d.lng)
        .ringMaxRadius((d) => radiusOf(d.value))
        .ringPropagationSpeed(2)
        .ringRepeatPeriod(1200);
      applyColours();
      // North-Atlantic framing (mirrors PEWPEW_GLOBE_ROTATE's intent):
      // view centre near [-10, 30] so US + EU + the attacker side read
      // together; altitude 2.2 frames the disc with margin.
      globe.pointOfView({ lat: 30, lng: -10, altitude: 2.2 }, 0);

      // Slow idle auto-rotate (DD-50): a gentle spin for the playful
      // pew-pew vibe. globe.gl's default controls are OrbitControls
      // (controlType 'orbit') and its render loop ticks controls.update()
      // each frame, so setting autoRotate is enough — no extra ticker.
      // Honour prefers-reduced-motion: a user who asks for less motion
      // gets a static (still draggable) globe. A user drag transiently
      // overrides the spin; OrbitControls resumes it on release. Left off
      // in v1 (DD-47) for screenshot stability — a one-shot
      // --virtual-time-budget capture still renders a single frame.
      const reduceMotion = typeof window.matchMedia === 'function'
        && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (!reduceMotion) {
        const controls = globe.controls();
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.6;   // ~100 s/revolution — gentle
      }

      resizeObs = new ResizeObserver(() => {
        if (!globe) return;
        globe.width(hostEl.clientWidth || 600)
          .height(hostEl.clientHeight || 400);
      });
      resizeObs.observe(hostEl);

      themeObs = new MutationObserver(applyColours);
      themeObs.observe(document.documentElement, {
        attributes: true, attributeFilter: ['data-theme'],
      });
    })
    .catch((err) => {
      console.warn('[misp-dashboard] globe.bundle load failed', err);
      if (!disposed) hostEl.innerHTML = placeholder('3D globe unavailable');
    });

  return {
    teardown() {
      disposed = true;
      if (themeObs) themeObs.disconnect();
      if (resizeObs) resizeObs.disconnect();
      if (globe && typeof globe._destructor === 'function') {
        globe._destructor();
      }
      hostEl.innerHTML = '';
    },
  };
}

const builders = {
  bar: buildBarOption,
  line: buildLineOption,
  geo: buildGeoOption,
  pie: buildPieOption,
  network: buildNetworkOption,
  // One builder, two modes (DD-45 mode switch): '2d' flat map or
  // '3d-globe' orthographic globe (DD-46) — see buildPewPewOption.
  pewpew: buildPewPewOption,
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

  // WebGL globe (DD-47): the opt-in 3D pew-pew mode. globe.gl owns its
  // own canvas + a lazy Three.js bundle, so it is NOT an ECharts builder
  // — branch before the ECharts path (and before ensureWorldMap, which
  // it doesn't need). initWebglGlobe returns a { teardown } handle
  // synchronously; the import resolves in the background behind a
  // loading placeholder, so only THIS mode is async-heavy — the 2d /
  // 3d-globe ECharts modes stay on the synchronous path below.
  if (kind === 'pewpew' && payload && payload.mode === 'webgl-globe') {
    liveCharts.set(el, initWebglGlobe(el, payload));
    return;
  }

  const builder = builders[kind];
  if (!builder) {
    console.warn(`[misp-dashboard] unknown chart kind "${kind}"`);
    return;
  }
  if (kind === 'geo' || kind === 'pewpew') {
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

/**
 * Re-theme every live chart inside `containerEl` after a light/dark
 * flip (DD-51). The CSS chrome and the WebGL globe retheme themselves —
 * the chrome via the cascade, the globe via its own MutationObserver on
 * <html data-theme> — but ECharts captures its theme palette at init
 * time and bakes token colours into the option at build time, so a
 * token change after boot is invisible until the chart is rebuilt.
 *
 * Approach: force-re-register the "misp" theme from the now-current
 * tokens, then re-init each ECharts container (initChart is idempotent —
 * it disposes the old instance and rebuilds from the unchanged DOM
 * payload under the new theme). The webgl-globe is skipped: it owns its
 * own canvas and self-rethemes live, so a re-init would needlessly tear
 * it down and refetch the 508 KB bundle/texture. Monitor charts do
 * re-init, resetting their short rolling buffer — an acceptable cost for
 * a rare, user-initiated toggle.
 */
export function rethemeChartsIn(containerEl) {
  if (!containerEl) return Promise.resolve();
  registerMispTheme(document.documentElement, true);
  const els = [...containerEl.querySelectorAll(`[${ATTR_CHART}]`)];
  const targets = els.filter((el) => {
    if (el.getAttribute(ATTR_CHART) !== 'pewpew') return true;
    let payload = {};
    try {
      payload = JSON.parse(el.getAttribute(ATTR_CHART_PAYLOAD) || '{}');
    } catch (_) { /* malformed → treat as a non-globe ECharts chart */ }
    return payload.mode !== 'webgl-globe';
  });
  return Promise.all(targets.map(initChart));
}
