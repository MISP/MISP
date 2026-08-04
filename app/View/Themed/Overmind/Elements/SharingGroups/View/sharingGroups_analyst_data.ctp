
<?php
App::uses('ClassRegistry', 'Utility');

$sgUuid = $data['SharingGroup']['uuid'] ?? '';
if ($sgUuid === '') {
    return;
}

$analystCount = ClassRegistry::init('Note')->countForObjectRecursive($me, $sgUuid);

echo $this->element('AnalystData/add_controls', [
    'objectType' => 'SharingGroup',
    'objectUuid' => $sgUuid,
    'viewCount'  => $analystCount,
]);