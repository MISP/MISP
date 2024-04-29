<?php
    $uuid = Hash::get($row, $field['data_path']);
    if (empty($uuid) || empty($field['object_type'])) {
        throw new MethodNotAllowedException(__('No UUID or object_type provided'), 500);
        
    }
    $notes = Hash::extract($row, $field['notes_data_path'] ?? 'Note');
    $opinions = Hash::extract($row, $field['opinions_data_path'] ?? 'Opnion');
    $relationships = Hash::extract($row, $field['relationships_data_path'] ?? 'Relationship');
    $relationshipsInbound = Hash::extract($row, $field['relationships_inbound_data_path'] ?? 'RelationshipInbound');
    echo $this->element('genericElements/shortUuidWithNotes', [
        'uuid' => $uuid,
        'object_type' => $field['object_type'],
        'notes' => $notes,
        'opinions' => $opinions,
        'relationships' => $relationships,
        'relationshipsInbound' => $relationshipsInbound,
    ]);