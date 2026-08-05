
<?php
App::uses('ClassRegistry', 'Utility');

$eventReportUuid = $data['EventReport']['uuid'] ?? '';
if ($eventReportUuid === '') {
    return;
}

$analystCount = ClassRegistry::init('Note')->countForObjectRecursive($me, $eventReportUuid);

echo $this->element('AnalystData/add_controls', [
    'objectType' => 'EventReport',
    'objectUuid' => $eventReportUuid,
    'viewCount'  => $analystCount,
]);
