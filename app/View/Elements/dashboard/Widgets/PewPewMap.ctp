<?php
/**
 * PewPewMap renderer (dashboard v2, DD-45) — "pew pew" attacker→victim
 * arcs.
 *
 * Dumb shim, consistent with the other ECharts render kinds (WorldMap,
 * BarChart, PieChart, NetworkGraph): it emits a `data-misp-chart`
 * host div whose JSON payload is dispatched client-side by
 * `charts.module.mjs`, which dispatches on `payload.mode`: `'2d'`
 * (default) draws the flat-map arcs and `'3d-globe'` swaps the geo
 * projection to a hemisphere-culling orthographic "2.5D" globe (DD-46,
 * d3-geo — no WebGL) via `buildPewPewOption`; `'webgl-globe'` (DD-47)
 * is a real WebGL globe via `initWebglGlobe` (globe.gl, lazy-loaded),
 * whose surface texture is chosen by `payload.skin` (DD-49). Same
 * `flows[]` payload across all modes.
 *
 * Expected $data shape (from PewPewMapWidget::handler()):
 *   [
 *     'mode'  => '2d' | '3d-globe' | 'webgl-globe',
 *     'skin'  => 'night' | 'day' | 'dark',   // webgl-globe only (DD-49)
 *     'flows' => [
 *       ['src' => [lon, lat], 'dst' => [lon, lat], 'value' => int,
 *        'src_iso' => 'XX', 'dst_iso' => 'YY'],
 *       ...
 *     ],
 *   ]
 *
 * Centroids are resolved server-side (DD-45 Phase B1), so the JS side
 * just plots the lon/lat pairs through ECharts' geo coordinate system.
 *
 * Aggregate-only posture (matches AttributeGeoMapWidget DD-11): no
 * `drilldown` map, no per-arc click handler — the arc resolution is
 * computed transiently per render so there is no stable arc→events
 * target. Colour resolution (arc body / destination glow) happens
 * client-side via the `tokenOn` helper, so a retoned/dark theme
 * recolours the arcs without touching this template.
 *
 * Empty `flows` → "No data." placeholder, mirroring WorldMap/BarChart.
 * A body-filling render kind: `.misp-chart` fills the widget body and
 * lets `.misp-widget-body` own scrolling.
 */
$flows = (isset($data['flows']) && is_array($data['flows'])) ? $data['flows'] : array();
if (empty($flows)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}
$mode = (isset($data['mode']) && is_string($data['mode'])) ? $data['mode'] : '2d';
// `skin` (DD-49) selects the webgl-globe surface texture; the 2d/
// 3d-globe modes ignore it. Must be passed through here or the JS
// always falls back to the default 'night' skin.
$skin = (isset($data['skin']) && is_string($data['skin'])) ? $data['skin'] : 'night';

$payload = array(
    'mode'  => $mode,
    'skin'  => $skin,
    'flows' => $flows,
);
?>
<div class="misp-chart"
     data-misp-chart="pewpew"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
