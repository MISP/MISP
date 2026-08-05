<?php
/**
 * BarChart renderer (dashboard v2) — ECharts shim.
 *
 * Emits a static chart container; the chart itself is created
 * client-side by `webroot/js/dashboard/charts/charts.module.mjs`
 * after the BoardModule injects this HTML via `innerHTML`. The
 * payload travels in a data-* attribute as JSON.
 *
 * Expected $data shape (TrendingTagsWidget non-overtime path, and the
 * v1 BarChart contract more generally):
 *   [
 *     'data'      => ['label' => count, ...],   // sorted by widget
 *     'colours'   => ['label' => '#hex', ...],  // optional override
 *     'drilldown' => ['label' => '/url', ...],  // optional DD-03
 *   ]
 *
 * `drilldown` (DD-03 per-datum carrier) maps a bar's category label to
 * a URL. Each URL is gated by `DashboardURLValidator`; unsafe entries
 * are silently dropped. Categories without a `drilldown` entry stay
 * non-clickable.
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');
$rows = isset($data['data']) ? $data['data'] : array();
if (empty($rows)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}
$drilldown = array();
if (isset($data['drilldown']) && is_array($data['drilldown'])) {
    foreach ($data['drilldown'] as $label => $url) {
        $safe = DashboardURLValidator::validate($url);
        if ($safe !== null) {
            $drilldown[(string)$label] = $safe;
        }
    }
}
$payload = array(
    'data'      => $rows,
    'colours'   => isset($data['colours']) ? $data['colours'] : array(),
    'drilldown' => $drilldown,
);
?>
<div class="misp-chart"
     data-misp-chart="bar"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
