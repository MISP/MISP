<?php
// TODO also output a kind of status code and data what was requested in the REST result
$xmlArray = array();

foreach ($events as $key => $event) {
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

// display the XML to the user
$xmlArray['response']['Event'] = $events;
$xmlArray['response']['xml_version'] = $mispVersion;
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
?><!--
Please note that this XML page is a representation of the /events/index page.
Because the /events/index page is paginated you will have a limited number of results.

You can for example ask: /events/index/limit:999.xml to get the 999 first records.

You can also sort the table by using the sort and direction parameters. For example:

/events/index/sort:date/direction:desc.xml

To export all the events at once, with their attributes, use the export functionality.
 -->
