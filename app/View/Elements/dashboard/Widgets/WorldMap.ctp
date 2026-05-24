<?php
/**
 * WorldMap renderer (dashboard v2) — ECharts geo shim.
 *
 * Replaces the v1 jvectormap renderer (`world_mill` SVG + jQuery).
 * The vendored Natural-Earth GeoJSON we ship at
 * `webroot/js/dashboard/charts/vendor/world-110m.geojson` keys
 * features by English `name` (e.g. "Bosnia and Herz."), while the
 * widget produces 2-letter ISO codes (e.g. "BA"). We translate
 * server-side using `WidgetToolkit::getCountryCodeMapping()` inverted,
 * so the JS side just feeds the data through to ECharts.
 *
 * Expected $data shape (from `OrganisationMapWidget::handler()`, and
 * the v1 WorldMap contract more generally):
 *   [
 *     'data'      => ['XX' => count, ...],  // 2-letter ISO alpha-2
 *     'scope'     => 'Organisations',        // tooltip prefix
 *     'drilldown' => ['XX' => '/url', ...],  // optional DD-03, ISO-keyed
 *   ]
 *
 * `drilldown` (DD-03 per-datum carrier) maps an ISO alpha-2 country
 * code to a URL. The renderer translates both the data and the
 * drilldown keys from ISO → English country name in lockstep so the
 * client looks up URLs by the same `params.name` it gets from
 * ECharts' click event. Each URL is gated by `DashboardURLValidator`;
 * unsafe entries are silently dropped. ISO codes the toolkit doesn't
 * know about are dropped from both data and drilldown (same posture
 * as v1).
 *
 * Empty `data` → "No data." placeholder, mirroring BarChart.
 */
App::uses('WidgetToolkit', 'Lib/Dashboard/Tools');
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');
$rows = isset($data['data']) ? $data['data'] : array();
if (empty($rows)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

// Invert the WidgetToolkit mapping ('Bosnia and Herz.' => 'BA') so we
// can look up GeoJSON-name from alpha-2. Codes the toolkit doesn't
// know about are silently dropped (same posture as v1).
$toolkit = new WidgetToolkit();
$nameByCode = array_flip($toolkit->getCountryCodeMapping());

$translated = array();
foreach ($rows as $code => $count) {
    if (isset($nameByCode[$code])) {
        $translated[$nameByCode[$code]] = (int)$count;
    }
}

if (empty($translated)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

// Translate drilldown keys ISO → English name in lockstep with $data,
// validating each URL. Codes the toolkit doesn't know about, or URLs
// the validator rejects, are silently dropped.
$drilldown = array();
if (isset($data['drilldown']) && is_array($data['drilldown'])) {
    foreach ($data['drilldown'] as $code => $url) {
        if (!isset($nameByCode[$code])) {
            continue;
        }
        $safe = DashboardURLValidator::validate($url);
        if ($safe !== null) {
            $drilldown[$nameByCode[$code]] = $safe;
        }
    }
}

$payload = array(
    'data'      => $translated,
    'scope'     => isset($data['scope']) ? $data['scope'] : '',
    'drilldown' => $drilldown,
);
?>
<div class="misp-chart"
     data-misp-chart="geo"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
