<?php
    $clusterId = $data['id'] ?? '';
    // Analyst relationships are gated on role alone, as analystData/add is.
    $canAnalyst = !empty($me['Role']['perm_add'])
        && !empty($me['Role']['perm_analyst_data']);
    $canGraph = $this->Acl->canAccess('analystData', 'add')
        && $this->Acl->canAccess('analystGraphs', 'save');

    // What a drawn analyst relationship or a saved graph can be shared with,
    // as the event page's explorer offers it.
    $analystSharing = ['levels' => [], 'sharingGroups' => [], 'default' => 1];
    $graphSharing = null;
    if ($canAnalyst || $canGraph) {
        $levels = $distributionLevels ?? ClassRegistry::init('Event')->distributionLevels;
        $sharing = ['levels' => [], 'sharingGroups' => []];
        foreach ([0, 1, 2, 3, 4] as $level) {
            if (isset($levels[$level])) {
                $sharing['levels'][] = [$level, $levels[$level]];
            }
        }
        $sgs = ClassRegistry::init('SharingGroup')->fetchAllAuthorised($me, 'name', 1);
        asort($sgs);
        foreach ($sgs as $sgId => $sgName) {
            $sharing['sharingGroups'][] = [(int)$sgId, $sgName];
        }
        if ($canAnalyst) {
            $analystSharing = $sharing + [
                'default' => (int)(Configure::read('MISP.default_analyst_data_distribution')
                    ?? Configure::read('MISP.default_event_distribution') ?? 1),
                'authors' => $me['email'] ?? '',
            ];
        }
        if ($canGraph) {
            App::uses('AnalystGraphDocumentTool', 'Tools');
            $graphSharing = $sharing + [
                'default' => (int)(Configure::read('MISP.default_analyst_data_distribution') ?? 1),
                'limits' => AnalystGraphDocumentTool::limits(),
            ];
        }
    }

    $pivotLabels = ClassRegistry::init('AnalystProfile')->pivotLabels($me);

    // Behaviour lives in webroot/js/cluster-pivot-explorer.js, which reads its
    // config from the data-cpe-* attributes on #cpe-card below.
    echo $this->element('genericElements/assetLoader', [
        'js'  => ['pivotick.iife', 'misp-pivot-nodes', 'pivot-sidebar-model', 'pivot-sidebar-view',
                  'pivot-explorer', 'cluster-pivot-explorer'],
        'css' => ['pivotick', 'pivot-explorer', 'pivot-sidebar'],
    ]);
?>

<div class="card shadow-sm mb-3" id="cpe-card"
     data-cpe-cluster-id="<?= h($clusterId) ?>"
     data-cpe-baseurl="<?= h($baseurl ?? '') ?>"
     data-cpe-can-analyst="<?= $canAnalyst ? '1' : '0' ?>"
     data-cpe-analyst-sharing="<?= h(json_encode($analystSharing)) ?>"
     data-cpe-graph-sharing="<?= h(json_encode($graphSharing)) ?>"
     data-cpe-label-plan="<?= h(json_encode($pivotLabels['plan'])) ?>"
     data-cpe-permitted="<?= h(json_encode($pivotLabels['permitted'])) ?>"
     data-cpe-org-uuid="<?= h($me['Organisation']['uuid'] ?? '') ?>"
     data-cpe-site-admin="<?= empty($me['Role']['perm_site_admin']) ? '0' : '1' ?>"
     data-cpe-value-card="<?= Configure::read('MISP.value_hover_card') ? '1' : '0' ?>"
     data-cpe-can-enrich="<?= $this->Acl->canAccess('values', 'enrichmentRun') ? '1' : '0' ?>"
     data-cpe-lib-missing="<?= h(__('Graph library failed to load.')) ?>"
     data-cpe-load-failed="<?= h(__('Failed to load the cluster graph.')) ?>"
     data-cpe-truncated-title="<?= h(__('Not every relation is drawn')) ?>"
     data-cpe-truncated="<?= h(__('The newest %s relations each way are on the canvas; pivot from the cluster for the rest.')) ?>">

    <div class="position-relative">
        <div id="cluster-pivot-explorer-loader" class="text-center py-5 text-muted">
            <div class="misp-loader mb-2" role="status"></div>
            <?= h(__('Building graph…')) ?>
        </div>
        <div id="cluster-pivot-explorer-graph"
             style="width:100%;height:72vh;min-height:480px;display:none;"></div>
    </div>
</div>
