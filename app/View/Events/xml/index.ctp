<?php
// TODO also output a kind of status code and data what was requested in the REST result
$xmlArray = array();
foreach ($events as $key => $event) {
	// rearrange things to be compatible with the Xml::fromArray()
	$events[$key] = $events[$key]['Event'];

	// cleanup the array from things we do not want to expose
	unset($events[$key]['Event']);
	// hide the private field is we are not in sync mode
	if ('true' != Configure::read('CyDefSIG.sync')) {
		unset($events[$key]['private']);
	}
	if ('true' == Configure::read('CyDefSIG.private')) {
		unset($events[$key]['cluster']);
		unset($events[$key]['sharing']);
	}
	// hide the org field is we are not in showorg mode
	if ('true' != Configure::read('CyDefSIG.showorg') && !$isAdmin) {
		unset($events[$key]['org']);
	}

}

// display the XML to the user
$xmlArray['response']['Event'] = $events;
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
?><!--
Please note that this XML page is a representation of the /events/index page.
Because the /events/index page is paginated you will have a limited number of results.

You can for example ask: /events/index/limit:999.xml to get the 999 first records.
(A maximum has been set to 9999)


To export all the events at once, with their attributes, use the export functionality.
 -->