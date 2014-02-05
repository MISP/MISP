<?php
$event['Event']['Attribute'] = $event['Attribute'];
unset($event['Attribute']);
$event['Event']['ShadowAttribute'] = $event['ShadowAttribute'];
unset($event['ShadowAttribute']);

unset($event['Event']['user_id']);
// hide the org field is we are not in showorg mode
if ('true' != Configure::read('MISP.showorg') && !$isAdmin) {
    unset($event['Event']['org']);
    unset($event['Event']['orgc']);
    unset($event['Event']['from']);
}

// remove value1 and value2 from the output
foreach ($event['Event']['Attribute'] as $key => $value) {
    unset($event['Event']['Attribute'][$key]['value1']);
    unset($event['Event']['Attribute'][$key]['value2']);
    unset($event['Event']['Attribute'][$key]['category_order']);
}
if (isset($event['Event']['RelatedEvent'])) {
    foreach ($event['Event']['RelatedEvent'] as $key => $value) {
        unset($event['Event']['RelatedEvent'][$key]['user_id']);
        if ('true' != Configure::read('MISP.showorg') && !$isAdmin) {
            unset($event['Event']['RelatedEvent'][$key]['org']);
            unset($event['Event']['RelatedEvent'][$key]['orgc']);
        }
    }
}

if (isset($relatedEvents)) {
    foreach ($relatedEvents as $relatedEvent) {
        $event['Event']['RelatedEvent'][] = $relatedEvent['Event'];
    }
}
echo json_encode($event);