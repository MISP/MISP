
<?php
$galaxyUuid = $data['uuid'] ?? '';
if ($galaxyUuid === '') {
    return;
}

echo $this->element('AnalystData/rail_card', [
    'objectType' => 'Galaxy',
    'objectUuid' => $galaxyUuid,
]);