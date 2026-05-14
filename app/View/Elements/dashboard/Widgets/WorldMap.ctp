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
 *     'data'  => ['XX' => count, ...],   // 2-letter ISO alpha-2
 *     'scope' => 'Organisations',         // tooltip prefix
 *   ]
 *
 * Empty `data` → "No data." placeholder, mirroring BarChart.
 */
App::uses('WidgetToolkit', 'Lib/Dashboard/Tools');
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

$payload = array(
    'data'  => $translated,
    'scope' => isset($data['scope']) ? $data['scope'] : '',
);
?>
<div class="misp-chart"
     data-misp-chart="geo"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
