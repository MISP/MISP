<?php

App::uses('ClassRegistry', 'Utility');

$eventUuid = $data['Event']['uuid'] ?? '';
if ($eventUuid === '') {
    return;
}

$analystCount = ClassRegistry::init('Note')->countForObjectRecursive($me, $eventUuid);

echo $this->element('AnalystData/add_controls', [
    'objectType' => 'Event',
    'objectUuid' => $eventUuid,
    'viewCount'  => $analystCount,
]);
