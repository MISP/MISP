<?php
echo $this->element('AnalystGraphs/graphs_card', [
    'targetType' => 'Collection',
    'targetUuid' => $data['Collection']['uuid'],
    'targetLabel' => $data['Collection']['name'],
    'canWorkspace' => $this->Acl->canAccess('collections', 'active')
        && ClassRegistry::init('Collection')->canModify($me, $data['Collection']),
]);
