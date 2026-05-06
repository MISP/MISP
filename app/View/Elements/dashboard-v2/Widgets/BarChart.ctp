<?php
/**
 * BarChart renderer (dashboard v2) — ECharts shim.
 *
 * Emits a static chart container; the chart itself is created
 * client-side by `webroot/js/dashboard-v2/charts/charts.module.mjs`
 * after the BoardModule injects this HTML via `innerHTML`. The
 * payload travels in a data-* attribute as JSON.
 *
 * Expected $data shape (TrendingTagsWidget non-overtime path, and the
 * v1 BarChart contract more generally):
 *   [
 *     'data'    => ['label' => count, ...],   // sorted by widget
 *     'colours' => ['label' => '#hex', ...],  // optional override
 *   ]
 *
 * Per-datum drilldown (DD-03) is intentionally not wired here yet —
 * Phase 5 task "ECharts click handlers calling drill-down" will route
 * `data['drilldown']` through `DashboardURLValidator`. Until then the
 * payload reaches the client untouched and the chart is non-clickable.
 */
$rows = isset($data['data']) ? $data['data'] : array();
if (empty($rows)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}
$payload = array(
    'data'    => $rows,
    'colours' => isset($data['colours']) ? $data['colours'] : array(),
);
?>
<div class="misp-chart"
     data-misp-chart="bar"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
