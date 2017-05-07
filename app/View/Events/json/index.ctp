<?php
foreach ($events as $key => $event) {
	// rearrange things to be compatible with the Xml::fromArray()
	$events[$key] = $events[$key]['Event'];
	unset($events[$key]['Event']);
	$events[$key]['Org'] = $event['Org'];
	$events[$key]['Orgc'] = $event['Orgc'];
	if (isset($event['GalaxyCluster'])) {
		$events[$key]['GalaxyCluster'] = $event['GalaxyCluster'];
	}
	if (isset($event['EventTag'])) $events[$key]['EventTag'] = $event['EventTag'];
	$events[$key]['SharingGroup'] = $event['SharingGroup'];

	// cleanup the array from things we do not want to expose
	unset($events[$key]['user_id']);
	// hide the org field if we are not in showorg mode
	if (!Configure::read('MISP.showorg')) {
		unset($events[$key]['Org']);
		unset($events[$key]['Orgc']);
	}
}
echo json_encode($events);
