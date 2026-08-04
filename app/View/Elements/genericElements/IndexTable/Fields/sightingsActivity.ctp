<?php

$object = Hash::extract($row, $field['data']['object']['value_path']);
$objectId = intval($object['id']);
$sightings = $field['sightings'];

if (!empty($sightings['csv'][$objectId])) {
    echo $this->element('sparkline', array('scope' => 'object', 'id' => $objectId, 'csv' => $sightings['csv'][$objectId]));
}
