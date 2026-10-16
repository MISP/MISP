
<?php
$eventReportUuid = $data['EventReport']['uuid'] ?? '';
if ($eventReportUuid === '') {
    return;
}

echo $this->element('AnalystData/rail_card', [
    'objectType' => 'EventReport',
    'objectUuid' => $eventReportUuid,
]);
