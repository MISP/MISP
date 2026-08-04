
<?php
App::uses('ClassRegistry', 'Utility');

$galaxyClusterUuid = $uuid ?? ($data['uuid'] ?? '');
if ($galaxyClusterUuid === '') {
    return;
}

$analystCount = ClassRegistry::init('Note')->countForObjectRecursive($me, $galaxyClusterUuid);

echo $this->element('AnalystData/add_controls', [
    'objectType' => 'GalaxyCluster',
    'objectUuid' => $galaxyClusterUuid,
    'viewCount'  => $analystCount,
]);