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
 * Expected $data shape (one current sample):
 *   [
 *     'value' => float,        // current reading; seeds the first point
 *     'label' => 'CPU',        // series name (tooltip)
 *     'unit'  => '%',          // axis/tooltip suffix
 *     'yMax'  => 100 | null,   // axis-ceiling FLOOR (expands above it if a
 *                              //   sample exceeds; null = fully auto-scaled)
 *   ]
 *
 * window_sec / interval_sec come from $config (schema defaults injected by
 * CanonicalTypeAdapter; user-overridable in the configure form). The poll
 * base URL is read client-side from the board root, so it is not emitted
 * here.
 */
$payload = array(
    'value'        => isset($data['value']) ? $data['value'] : null,
    'label'        => isset($data['label']) ? $data['label'] : __('value'),
    'unit'         => isset($data['unit']) ? $data['unit'] : '',
    'yMax'         => array_key_exists('yMax', $data) ? $data['yMax'] : null,
    'window_sec'   => isset($config['window']) ? (int)$config['window'] : 180,
    'interval_sec' => isset($config['interval']) ? (int)$config['interval'] : 10,
);
?>
<div class="misp-chart"
     data-misp-chart="monitor"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
