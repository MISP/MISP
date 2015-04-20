<?php
foreach ($events as $key => &$event) {
    // rearrange things to be compatible with the Xml::fromArray()
    $events[$key] = $events[$key]['Event'];
    unset($events[$key]['Event']);

    // cleanup the array from things we do not want to expose
    unset($events[$key]['user_id']);
    // hide the org field is we are not in showorg mode
    if (!Configure::read('MISP.showorg') && !$isAdmin) {
        unset($events[$key]['Org']);
        unset($events[$key]['Orgc']);
        unset($events[$key]['from']);
    }

}
echo json_encode($events);