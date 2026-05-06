// dashboard-v2 — ECharts "misp" theme registration.
//
// PRD §8.2 (Level 2 theming): the dashboard registers a single named
// ECharts theme whose palette and axis colours are derived at boot
// from the CSS custom properties (`--misp-dash-*`) defined on `:root`
// in `webroot/css/dashboard/dashboard.default.css`. A CSS-only theme
// that only redefines those tokens therefore gets themed charts for
// free — without writing any JS.
//
// Heavier themes that want finer chart control ship their own ECharts
// theme JSON and register it under a different name; that integration
// path lands in Phase 1 (toolbar / `MISP.theme_echarts_name` lookup).

import echarts from './vendor/echarts.bundle.mjs';

export const MISP_THEME_NAME = 'misp';

let registered = false;

/**
 * Register the "misp" ECharts theme. Idempotent — first caller wins.
 * `scopeEl` defaults to `document.documentElement` since v2 tokens are
 * declared on `:root`; passing a more specific element only matters
 * when a wrapper class redefines tokens locally (PRD §8.1).
 */
export function registerMispTheme(scopeEl) {
  if (registered) return MISP_THEME_NAME;
  const cs = getComputedStyle(scopeEl || document.documentElement);
  const tok = (name, fallback) => {
    const v = cs.getPropertyValue(name).trim();
    return v || fallback;
  };
  const accent  = tok('--misp-dash-accent',         '#2563eb');
  const success = tok('--misp-dash-success',        '#16a34a');
  const danger  = tok('--misp-dash-danger',         '#dc2626');
  const warning = tok('--misp-dash-warning',        '#d97706');
  const info    = tok('--misp-dash-info',           '#0891b2');
  const text    = tok('--misp-dash-text',           '#1d2025');
  const muted   = tok('--misp-dash-text-muted',     '#6b7280');
  const border  = tok('--misp-dash-border',         '#d8dde4');
  const surface = tok('--misp-dash-surface-raised', '#ffffff');

  echarts.registerTheme(MISP_THEME_NAME, {
    color: [accent, success, warning, info, danger, muted],
    backgroundColor: 'transparent',
    textStyle: { color: text },
    title: {
      textStyle:    { color: text },
      subtextStyle: { color: muted },
    },
    legend:  { textStyle: { color: text } },
    tooltip: {
      backgroundColor: surface,
      borderColor:     border,
      textStyle:       { color: text },
    },
    categoryAxis: {
      axisLine:  { lineStyle: { color: border } },
      axisTick:  { lineStyle: { color: border } },
      axisLabel: { color: muted },
      splitLine: { lineStyle: { color: border, type: 'dashed' } },
    },
    valueAxis: {
      axisLine:  { lineStyle: { color: border } },
      axisTick:  { lineStyle: { color: border } },
      axisLabel: { color: muted },
      splitLine: { lineStyle: { color: border, type: 'dashed' } },
    },
    bar:  { itemStyle: { borderRadius: [3, 3, 0, 0] } },
    line: { itemStyle: { borderWidth: 0 }, lineStyle: { width: 2 } },
  });
  registered = true;
  return MISP_THEME_NAME;
}
