
<?php
$sgUuid = $data['SharingGroup']['uuid'] ?? '';
if ($sgUuid === '') {
    return;
}

echo $this->element('AnalystData/rail_card', [
    'objectType' => 'SharingGroup',
    'objectUuid' => $sgUuid,
]);