<?php
	echo $this->Form->create('Sighting', array('id' => 'Sighting_' . $id, 'url' => '/sightings/add/' . $id, 'style' => 'display:none;'));
	echo $this->Form->end();
?>
