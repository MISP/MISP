<?php
$collectionUuid = $data['Collection']['uuid'] ?? '';
if ($collectionUuid === '') {
    return;
}

echo $this->element('AnalystData/rail_card', [
    'objectType' => 'Collection',
    'objectUuid' => $collectionUuid,
]);
