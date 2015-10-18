<?php
foreach ($events as $key => &$event) {
    // rearrange things to be compatible with the Xml::fromArray()
    $events[$key]['Event']['Org'] = $events[$key]['Org'];
    $events[$key]['Event']['Orgc'] = $events[$key]['Orgc'];
    $events[$key]['Event']['EventTag'] = $events[$key]['EventTag'];
    $events[$key]['Event']['SharingGroup'] = $events[$key]['SharingGroup'];
    $events[$key] = $events[$key]['Event'];
    unset($events[$key]['Event']);

    // cleanup the array from things we do not want to expose
    unset($events[$key]['user_id']);
    // hide the org field is we are not in showorg mode
    if (!Configure::read('MISP.showorg')) {
        unset($events[$key]['Org']);
        unset($events[$key]['Orgc']);
    }

}
echo json_encode($events);