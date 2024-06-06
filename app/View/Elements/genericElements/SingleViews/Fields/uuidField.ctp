<?php
    $uuid = Hash::extract($data, $field['path'])[0];
    echo sprintf(
        '<span class="quickSelect">%s</span>',
        h($uuid)
    );
    
    if (!empty($field['object_type'])) {
        $field['notes_path'] = !empty($field['notes_path']) ? $field['notes_path'] : 'Note';
        $field['opinions_path'] = !empty($field['opinions_path']) ? $field['opinions_path'] : 'Opinion';
        $field['relationships_path'] = !empty($field['relationships_path']) ? $field['relationships_path'] : 'Relationship';
        $field['relationshipsInbound_path'] = !empty($field['relationshipsInbound_path']) ? $field['relationshipsInbound_path'] : 'RelationshipInbound';
        $notes = !empty($field['notes']) ? $field['notes'] : Hash::extract($data, $field['notes_path']);
        $opinions = !empty($field['opinions']) ? $field['opinions'] : Hash::extract($data, $field['opinions_path']);
        $relationships = !empty($field['relationships']) ? $field['relationships'] : Hash::extract($data, $field['relationships_path']);
        $relationshipsInbound = !empty($field['relationshipsInbound']) ? $field['relationshipsInbound'] : Hash::extract($data, $field['relationshipsInbound_path']);
        echo $this->element('genericElements/Analyst_data/generic', [
            'analyst_data' => ['notes' => $notes, 'opinions' => $opinions, 'relationships_outbound' => $relationships, 'relationships_inbound' => $relationshipsInbound],
            'object_uuid' => $uuid,
            'object_type' => $field['object_type']
        ]);
    }
