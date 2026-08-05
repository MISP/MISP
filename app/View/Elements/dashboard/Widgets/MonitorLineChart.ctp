<?php
/**
 * MonitorLineChart renderer (dashboard v2) — streaming single-series line.
 *
 * Emits a chart container of kind "monitor"; monitor-chart.mjs creates the
 * ECharts line, seeds it with the initial sample below, then polls THIS
 * widget's handler every interval_sec (via the existing renderWidget
 * `exportjson` contract) to accumulate a rolling window_sec series
 * CLIENT-SIDE while the dashboard is open. The widget sets
 * autoRefreshDelay=false so the board scheduler never re-renders (and
 * resets) the tile — the chart's own poll loop is the sole driver.
 *
 * Expected $data shape (DD-30 — server-persisted history):
 *   [
 *     'history' => [[ts, value], ...],  // Redis-retained series (oldest
 *                                       //   first); seeds + repaints the chart
 *     'label'   => 'CPU',               // series name (tooltip)
 *     'unit'    => '%',                 // axis/tooltip suffix
 *     'yMax'    => 100 | null,          // axis-ceiling FLOOR (expands above it
 *                                       //   if a sample exceeds; null = auto)
 *   ]
 *
 * interval_sec comes from $config (schema default injected by
 * CanonicalTypeAdapter; user-overridable in the configure form) and drives
 * the client's poll cadence (the window is enforced server-side). The poll
 * base URL is read client-side from the board root, so it is not emitted
 * here.
 */
$payload = array(
    'history'      => (isset($data['history']) && is_array($data['history'])) ? $data['history'] : array(),
    'label'        => isset($data['label']) ? $data['label'] : __('value'),
    'unit'         => isset($data['unit']) ? $data['unit'] : '',
    'yMax'         => array_key_exists('yMax', $data) ? $data['yMax'] : null,
    'interval_sec' => isset($config['interval']) ? (int)$config['interval'] : 10,
);
?>
<div class="misp-chart"
     data-misp-chart="monitor"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
