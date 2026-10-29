<?php
$headControl = null;
if ($this->Acl->canAccess('collectionElements', 'addItems')) {
    $headControl = '<div data-tour="event-investigations-add">' . $this->element('intel_graph_add', [
        'items' => [['type' => 'Event', 'uuid' => $data['Event']['uuid'], 'label' => $data['Event']['info']]],
        'variant' => 'short',
        'title' => __('Add this event to your workspace'),
    ]) . '</div>';
}
echo $this->element('AnalystGraphs/graphs_card', [
    'targetType' => 'Event',
    'targetUuid' => $data['Event']['uuid'],
    'targetLabel' => $data['Event']['info'],
    'investigations' => true,
    'headControl' => $headControl,
]);
