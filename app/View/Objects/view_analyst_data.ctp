<?php
    $notes = !empty($object['Note']) ? $object['Note'] : [];
    $opinions = !empty($object['Opinion']) ? $object['Opinion'] : [];
    $relationships = !empty($object['Relationship']) ? $object['Relationship'] : [];
    $relationshipsInbound = !empty($object['RelationshipInbound']) ? $object['RelationshipInbound'] : [];
    echo $this->element('genericElements/Analyst_data/generic_simple', [
        'analyst_data' => ['notes' => $notes, 'opinions' => $opinions, 'relationships_outbound' => $relationships, 'relationships_inbound' => $relationshipsInbound],
        'object_uuid' => $object['uuid'],
        'object_type' => 'Object'
    ]);
?>