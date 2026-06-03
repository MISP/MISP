<?php
/**
 * PieChart renderer (dashboard v2) — ECharts shim.
 *
 * Emits a static chart container; the donut is created client-side by
 * webroot/js/dashboard/charts/charts.module.mjs (kind "pie") after the
 * BoardModule injects this HTML via innerHTML. The payload travels in a
 * data-* attribute as JSON.
 *
 * Expected $data shape:
 *   [
 *     'slices'    => ['Label' => numericValue, ...],  // summed into a pie
 *     'colours'   => ['Label' => '#hex', ...],        // optional override
 *     'used_pct'  => float,                           // optional centre label
 *     'threshold' => int,                             // optional; over →
 *                                                     //   Used slice red
 *     'error'     => 'message',                        // optional empty-state
 *   ]
 *
 * The client recolours the conventional "Used" slice with the danger
 * token when used_pct exceeds threshold; everything else falls back to
 * the accent / border tokens so themes retone the chart.
 */
$slices = (isset($data['slices']) && is_array($data['slices'])) ? $data['slices'] : array();
if (empty($slices)) {
    $msg = !empty($data['error']) ? h($data['error']) : __('No data.');
    echo '<div class="misp-list-empty">' . $msg . '</div>';
    return;
}
$payload = array(
    'slices'    => $slices,
    'colours'   => isset($data['colours']) ? $data['colours'] : array(),
    'used_pct'  => isset($data['used_pct']) ? $data['used_pct'] : null,
    'threshold' => isset($data['threshold']) ? $data['threshold'] : null,
);
?>
<div class="misp-chart"
     data-misp-chart="pie"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
