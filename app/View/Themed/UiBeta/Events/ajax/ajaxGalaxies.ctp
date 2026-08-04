<?php
if (!empty($object['Galaxy'])):
    $subClustersByGalaxy = [];
    foreach ($object['Galaxy'] as $galaxy) {
        foreach ($galaxy['GalaxyCluster'] as $cluster) {
            $subClustersByGalaxy[$galaxy['name']][] = $cluster;
        }
    }

    // Determine permissions and target context
    $ajaxCanModify = false;
    $ajaxCanModifyLocal = false;
    $ajaxTargetType = $scope ?? null;
    $ajaxTargetId = null;

    if ($ajaxTargetType === 'event' && !empty($object['Event']['id'])) {
        $ajaxCanModify = $this->Acl->canModifyTag($object);
        $ajaxCanModifyLocal = $this->Acl->canModifyTag($object, true);
        $ajaxTargetId = $object['Event']['id'];
    } elseif ($ajaxTargetType === 'attribute' && !empty($object['Attribute']['id'])) {
        $ajaxCanModify = $this->Acl->canModifyTag($object);
        $ajaxCanModifyLocal = $this->Acl->canModifyTag($object, true);
        $ajaxTargetId = $object['Attribute']['id'];
    }

    foreach ($subClustersByGalaxy as $galaxyName => $clusters):
        echo $this->element('Events/View/galaxy_compact_beta', [
            'galaxyName' => $galaxyName,
            'clusters' => $clusters,
            'baseurl' => $baseurl,
            'canModify' => $ajaxCanModify,
            'canModifyLocal' => $ajaxCanModifyLocal,
            'target_type' => $ajaxTargetType,
            'target_id' => $ajaxTargetId,
        ]);
    endforeach;
endif;
