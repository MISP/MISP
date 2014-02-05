<?php
$xmlArray = array();
// rearrange things to be compatible with the Xml::fromArray()
$event['Event']['Attribute'] = $event['Attribute'];
unset($event['Attribute']);
$event['Event']['ShadowAttribute'] = $event['ShadowAttribute'];
unset($event['ShadowAttribute']);

// build up a list of the related events
if (isset($relatedEvents)) {
    foreach ($relatedEvents as $relatedEvent) {
        $event['Event']['RelatedEvent'][] = $relatedEvent['Event'];
    }
}

//
// cleanup the array from things we do not want to expose
//
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

// display the XML to the user
$xmlArray['response']['Event'][] = $event['Event'];
$xmlArray['response']['xml_version'] = $mispVersion;
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
