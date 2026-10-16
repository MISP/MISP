<?php
echo $this->element('AnalystGraphs/graphs_card', [
    'targetType' => 'GalaxyCluster',
    'targetUuid' => $data['uuid'],
    'targetLabel' => $data['value'],
]);
