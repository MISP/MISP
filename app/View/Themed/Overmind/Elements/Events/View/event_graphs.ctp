<?php
echo $this->element('AnalystGraphs/graphs_card', [
    'targetType' => 'Event',
    'targetUuid' => $data['Event']['uuid'],
    'targetLabel' => $data['Event']['info'],
]);
