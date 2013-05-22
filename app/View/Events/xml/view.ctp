<?php
$xmlArray = array();
// rearrange things to be compatible with the Xml::fromArray()
$event['Event']['Attribute'] = $event['Attribute'];
unset($event['Attribute']);

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
unset($event['Event']['cluster']);
unset($event['Event']['private']);
unset($event['Event']['communitie']);
// hide the org field is we are not in showorg mode
if ('true' != Configure::read('CyDefSIG.showorg') && !$isAdmin) {
    unset($event['Event']['org']);
    unset($event['Event']['orgc']);
    unset($event['Event']['from']);
}

// remove value1 and value2 from the output
foreach ($event['Event']['Attribute'] as $key => $value) {
	unset($event['Event']['Attribute'][$key]['private']);
	unset($event['Event']['Attribute'][$key]['communitie']);
	unset($event['Event']['Attribute'][$key]['cluster']);

	unset($event['Event']['Attribute'][$key]['value1']);
	unset($event['Event']['Attribute'][$key]['value2']);

	unset($event['Event']['Attribute'][$key]['category_order']);
}
foreach ($event['Event']['RelatedEvent'] as $key => $value) {
	unset($event['Event']['RelatedEvent'][$key]['user_id']);
	unset($event['Event']['RelatedEvent'][$key]['private']);
	unset($event['Event']['RelatedEvent'][$key]['communitie']);
	unset($event['Event']['RelatedEvent'][$key]['cluster']);
	if ('true' != Configure::read('CyDefSIG.showorg') && !$isAdmin) {
	    unset($event['Event']['RelatedEvent'][$key]['org']);
	    unset($event['Event']['RelatedEvent'][$key]['orgc']);
	    unset($event['Event']['RelatedEvent'][$key]['from']);
	}
}

// display the XML to the user
$xmlArray['response']['Event'][] = $event['Event'];
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
