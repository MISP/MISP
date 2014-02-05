<?php
foreach ($events as $key => &$event) {
    // rearrange things to be compatible with the Xml::fromArray()
    $events[$key] = $events[$key]['Event'];
    unset($events[$key]['Event']);

    // cleanup the array from things we do not want to expose
    unset($events[$key]['user_id']);
    // hide the org field is we are not in showorg mode
    if ('true' != Configure::read('MISP.showorg') && !$isAdmin) {
        unset($events[$key]['org']);
        unset($events[$key]['orgc']);
        unset($events[$key]['from']);
    }

}
echo json_encode($events);