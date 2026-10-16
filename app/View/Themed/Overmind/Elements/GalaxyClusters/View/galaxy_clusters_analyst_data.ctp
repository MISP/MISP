
<?php
$galaxyClusterUuid = $uuid ?? ($data['uuid'] ?? '');
if ($galaxyClusterUuid === '') {
    return;
}

echo $this->element('AnalystData/rail_card', [
    'objectType' => 'GalaxyCluster',
    'objectUuid' => $galaxyClusterUuid,
]);