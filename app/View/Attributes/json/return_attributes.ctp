<?php
$jsonArray = array();
foreach ($results as $k => $v) {
	unset(
			$results[$k]['value1'],
			$results[$k]['value2']
	);
	$jsonArray['response']['Attribute'][] = $results[$k];
}
echo json_encode($jsonArray);
