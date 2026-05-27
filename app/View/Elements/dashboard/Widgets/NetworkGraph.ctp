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
 *        'status' => 'self'|'ok'|'warn'|'error', 'message' => '...'],
 *       ...
 *     ],
 *     'links' => [ ['source' => <id>, 'target' => <id>], ... ],
 *     'error' => 'message',   // optional empty-state
 *   ]
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
