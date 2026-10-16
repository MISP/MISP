<?php
    $eventId  = $data['Event']['id'] ?? '';
    // Drawing references is only offered when the viewer may modify the
    // event (same ACL the ObjectReferences add endpoint enforces).
    $canEdit  = $this->Acl->canModifyEvent($data);
    // Analyst relationships are gated on role alone, as analystData/add is.
    $canAnalyst = !empty($me['Role']['perm_add'])
        && !empty($me['Role']['perm_analyst_data']);
    // Tagging is offered as the event page's tag card offers it; the
    // event's own attributes answer the same as the event.
    $canTag = $this->Acl->canModifyTag($data)
        && $this->Acl->canAccess('events', 'editEventTags')
        && $this->Acl->canAccess('attributes', 'editAttributeTags');
    $canCluster = $this->Acl->canModifyTag($data)
        && $this->Acl->canAccess('events', 'editEventGalaxies')
        && $this->Acl->canAccess('attributes', 'editAttributeGalaxies');
    $canGraph = $this->Acl->canAccess('analystData', 'add')
        && $this->Acl->canAccess('analystGraphs', 'save');

    // What a drawn analyst relationship or a saved graph can be shared with,
    // as analystData/add offers it: levels 0-4 (no inherit), the user's
    // usable sharing groups by name, and the instance's default.
    $analystSharing = ['levels' => [], 'sharingGroups' => [], 'default' => 1];
    $graphSharing = null;
    if ($canAnalyst || $canGraph) {
        App::uses('ClassRegistry', 'Utility');
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

    // Which attribute an object node leads with, per template relation.
    $uiPriorities = $eventId === '' ? [] : ClassRegistry::init('ObjectTemplate')
        ->uiPrioritiesForEvent($me, $eventId);

    // The sidebar orders tags and clusters by the viewer's analyst profile,
    // as the event page does, and names a pin the node lacks only when the
    // instance has that taxonomy or galaxy enabled.
    // view2 does not run __eventViewCommon, which sets it for the other views.
    $pivotLabels = ClassRegistry::init('AnalystProfile')->pivotLabels($me, $labelPlan ?? null);
    $labelPlan = $pivotLabels['plan'];
    $permitted = $pivotLabels['permitted'];

    // Behaviour lives in webroot/js/pivot-explorer.js, which reads its
    // config from the data-pe-* attributes on #pe-card below.
    echo $this->element('genericElements/assetLoader', [
        'js'  => ['pivotick.iife', 'misp-pivot-nodes', 'pivot-sidebar-model', 'pivot-sidebar-view', 'pivot-explorer'],
        'css' => ['pivotick', 'pivot-explorer', 'pivot-sidebar'],
    ]);
?>

<div class="card shadow-sm mb-3" id="pe-card" data-tour="event-pivot-explorer"
     data-pe-event-id="<?= h($eventId) ?>"
     data-pe-baseurl="<?= h($baseurl ?? '') ?>"
     data-pe-can-edit="<?= $canEdit ? '1' : '0' ?>"
     data-pe-can-analyst="<?= $canAnalyst ? '1' : '0' ?>"
     data-pe-can-tag="<?= $canTag ? '1' : '0' ?>"
     data-pe-can-cluster="<?= $canCluster ? '1' : '0' ?>"
     data-pe-analyst-sharing="<?= h(json_encode($analystSharing)) ?>"
     data-pe-graph-sharing="<?= h(json_encode($graphSharing)) ?>"
     data-pe-ui-priorities="<?= h(json_encode((object)$uiPriorities)) ?>"
     data-pe-label-plan="<?= h(json_encode($labelPlan)) ?>"
     data-pe-permitted="<?= h(json_encode($permitted)) ?>"
     data-pe-org-uuid="<?= h($me['Organisation']['uuid'] ?? '') ?>"
     data-pe-site-admin="<?= empty($me['Role']['perm_site_admin']) ? '0' : '1' ?>"
     data-pe-value-card="<?= Configure::read('MISP.value_hover_card') ? '1' : '0' ?>"
     data-pe-can-enrich="<?= $this->Acl->canAccess('values', 'enrichmentRun') ? '1' : '0' ?>"
     data-pe-lib-missing="<?= h(__('Graph library failed to load.')) ?>"
     data-pe-load-failed="<?= h(__('Failed to load event graph.')) ?>">

    <!-- BODY -->
    <div class="position-relative" id="pe-stage">

        <!-- Loader -->
        <div id="pivot-explorer-loader" class="text-center py-5 text-muted">
            <div class="misp-loader mb-2" role="status"></div>
            <?= h(__('Building graph…')) ?>
        </div>

        <!-- Graph container (revealed after fetch) -->
        <div id="pivot-explorer-graph"
             style="width:100%;height:72vh;min-height:480px;display:none;"></div>
    </div>
</div>

