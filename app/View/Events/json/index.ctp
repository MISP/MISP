<?php
foreach ($events as $key => $event) {
    // rearrange things to be compatible with the Xml::fromArray()
    $events[$key] = $events[$key]['Event'];
    unset($events[$key]['Event']);
    $events[$key]['Org'] = $event['Org'];
    $events[$key]['Orgc'] = $event['Orgc'];
    if (isset($event['GalaxyCluster'])) {
        $events[$key]['GalaxyCluster'] = $event['GalaxyCluster'];
    }
    if (isset($event['EventTag'])) $events[$key]['EventTag'] = $event['EventTag'];
    if (!empty($event['SharingGroup'])) {
        $events[$key]['SharingGroup'] = $event['SharingGroup'];
    }
    unset($events[$key]['user_id']);
}
echo json_encode($events);
