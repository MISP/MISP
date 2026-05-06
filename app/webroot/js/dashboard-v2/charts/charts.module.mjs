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

const builders = {
  bar: buildBarOption,
};

// ---- public API ----

/**
 * Initialise every chart container found inside `containerEl`.
 * Idempotent: re-initialising over an already-live chart disposes the
 * old instance first.
 */
export function initChartsIn(containerEl) {
  if (!containerEl) return;
  registerMispTheme();
  const els = containerEl.querySelectorAll(`[${ATTR_CHART}]`);
  for (const el of els) {
    if (liveCharts.has(el)) disposeChart(el);
    const kind = el.getAttribute(ATTR_CHART);
    const builder = builders[kind];
    if (!builder) {
      console.warn(`[misp-dashboard] unknown chart kind "${kind}"`);
      continue;
    }
    let payload = {};
    try {
      payload = JSON.parse(el.getAttribute(ATTR_CHART_PAYLOAD) || '{}');
    } catch (err) {
      console.warn(`[misp-dashboard] malformed chart payload`, err);
    }
    const chart = echarts.init(el, MISP_THEME_NAME, { renderer: 'canvas' });
    chart.setOption(builder(payload));

    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(el);
    liveCharts.set(el, { chart, observer });
  }
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
