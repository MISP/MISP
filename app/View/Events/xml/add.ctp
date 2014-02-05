<?php
$xmlArray = array();
// rearrange things to be compatible with the Xml::fromArray()
$event['Event']['Attribute'] = $event['Attribute'];
unset($event['Attribute']);

// cleanup the array from things we do not want to expose
// remove value1 and value2 from the output
foreach ($event['Event']['Attribute'] as $key => $value) {
	unset($event['Event']['Attribute'][$key]['value1']);
	unset($event['Event']['Attribute'][$key]['value2']);
	unset($event['Event']['Attribute'][$key]['category_order']);
}

// hide the private fields is we are not in sync mode
if ('true' != Configure::read('MISP.sync')) {
	unset($event['Event']['private']);
	foreach ($event['Event']['Attribute'] as $key => $value) {
		unset($event['Event']['Attribute'][$key]['private']);
	}
}
// hide the org field is we are not in showorg mode
if ('true' != Configure::read('MISP.showorg') && !$isAdmin) {
	unset($event['Event']['org']);
}

// build up a list of the related events
if (isset($relatedEvents)) {
	foreach ($relatedEvents as $relatedEvent) {
		$event['Event']['RelatedEvent'][] = $relatedEvent['Event'];
	}
}

// display the XML to the user
$xmlArray['response']['Event'][] = $event['Event'];
$xmlArray['response']['xml_version'] = $mispVersion;
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
