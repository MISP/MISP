<?php
	$extensions = array('redis');
	$results = array();
	$results['phpversion'] = phpversion();
	foreach ($extensions as $extension) {
		$results['extensions'][$extension] = extension_loaded($extension);
	}
	echo json_encode($results);

?>
