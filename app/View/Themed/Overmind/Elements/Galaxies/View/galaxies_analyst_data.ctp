
<?php
App::uses('ClassRegistry', 'Utility');

$galaxyUuid = $data['uuid'] ?? '';
if ($galaxyUuid === '') {
    return;
}

$analystCount = ClassRegistry::init('Note')->countForObjectRecursive($me, $galaxyUuid);

echo $this->element('AnalystData/add_controls', [
    'objectType' => 'Galaxy',
    'objectUuid' => $galaxyUuid,
    'viewCount'  => $analystCount,
]);