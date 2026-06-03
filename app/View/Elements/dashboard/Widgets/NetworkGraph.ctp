<?php
/**
 * NetworkGraph renderer (dashboard v2) — ECharts graph shim.
 *
 * Emits a static chart container; the node/edge graph is built
 * client-side by webroot/js/dashboard/charts/charts.module.mjs
 * (kind "network", builder buildNetworkOption) after the BoardModule
 * injects this HTML via innerHTML. The payload travels in a data-*
 * attribute as JSON.
 *
 * A hub-and-spoke diagram: the `self` node (the current instance) is the
 * centre, the remaining nodes ring around it, edges connect them. Node
 * colour comes from `status` via semantic theme tokens; the tooltip
 * shows each node's name, URL and test outcome.
 *
 * Expected $data shape:
 *   [
 *     'nodes' => [
 *       ['id' => 'self', 'name' => '...', 'url' => '...',
 *        'status' => 'self'|'ok'|'warn'|'error'|'info',
 *        'kind'   => 'server'|'feed',  // optional, default 'server'
 *        'message' => '...'],
 *       ...
 *     ],
 *     'links' => [ ['source' => <id>, 'target' => <id>], ... ],
 *     'error' => 'message',   // optional empty-state
 *   ]
 *
 * `kind` (DD-40) selects the node glyph: `server` is the default
 * server-rack from DD-33; `feed` is an RSS-waves glyph for feed
 * sources. The hub node always renders as `server` regardless of
 * the `kind` field — the diagram centre is a MISP instance.
 *
 * `status` `info` (DD-40) is a fifth tier mapped to
 * `--misp-dash-info` (cyan), used by cache-freshness rollups.
 *
 * Requires GraphChart in the vendored ECharts bundle (a `type:'graph'`
 * series renders nothing otherwise — see vendor/VENDORING.md, DD-33).
 */
$nodes = (isset($data['nodes']) && is_array($data['nodes'])) ? $data['nodes'] : array();
if (empty($nodes)) {
    $msg = !empty($data['error']) ? h($data['error']) : __('No data.');
    echo '<div class="misp-list-empty">' . $msg . '</div>';
    return;
}
$payload = array(
    'nodes' => $nodes,
    'links' => (isset($data['links']) && is_array($data['links'])) ? $data['links'] : array(),
);
?>
<div class="misp-chart"
     data-misp-chart="network"
     data-misp-chart-payload="<?= h(json_encode($payload, JSON_UNESCAPED_SLASHES)) ?>"></div>
