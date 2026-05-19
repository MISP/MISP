<?php
/**
 * MultiLineChart renderer (dashboard v2) — ECharts shim.
 *
 * Same pattern as BarChart: emits a static chart container; the chart
 * itself is created client-side by `webroot/js/dashboard/charts/
 * charts.module.mjs` after the BoardModule injects this HTML via
 * `innerHTML`. The payload travels in a data-* attribute as JSON.
 *
 * Expected $data shape (TrendingTagsWidget over_time path is the
 * canonical producer; OrgEvolutionLineWidget / EventEvolutionLineWidget
 * / OrgsEvolutionWidget / UsersEvolutionWidget follow the same row
 * shape):
 *   [
 *     'data' => [
 *       ['date' => 'YYYY-MM-DD', 'lineA' => 3, 'lineB' => 0, ...],
 *       ['date' => 'YYYY-MM-DD', 'lineA' => 1, 'lineB' => 5, ...],
 *       ...
 *     ],
 *     'colours' => ['lineA' => '#hex', ...],   // optional override
 *     'formula' => 'optional headline string', // optional
 *     'y-axis'  => 'Count',                    // optional, default 'Count'
 *   ]
 *
 * Per-line drilldown (DD-03) is intentionally not wired here yet —
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
    'yAxis'   => isset($data['y-axis']) ? $data['y-axis'] : 'Count',
);
if (!empty($data['formula'])) {
    echo sprintf(
        '<div class="misp-chart-formula">%s</div>',
        h($data['formula'])
    );
}
?>
<div class="misp-chart"
     data-misp-chart="line"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
