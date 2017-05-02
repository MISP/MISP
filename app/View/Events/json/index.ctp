<?php
foreach ($events as $key => $event) {
    // rearrange things to be compatible with the Xml::fromArray()
    // $events[$key] = $events[$key]['Event'];
    // unset($events[$key]['Event']);
    $events[$key]['Event']['Org'] = $event['Org'];
    $events[$key]['Event']['Orgc'] = $event['Orgc'];
    if (isset($event['Event']['GalaxyCluster'])) {
    	$events[$key]['Event']['GalaxyCluster'] = $event['GalaxyCluster'];
    }
    if (isset($event['EventTag'])) $events[$key]['Event']['EventTag'] = $event['EventTag'];
    $events[$key]['Event']['SharingGroup'] = $event['SharingGroup'];

    // cleanup the array from things we do not want to expose
    unset($events[$key]['user_id']);
    // hide the org field is we are not in showorg mode
    if (!Configure::read('MISP.showorg')) {
        unset($events[$key]['Org']);
        unset($events[$key]['Orgc']);
    }
}
echo json_encode($events);
