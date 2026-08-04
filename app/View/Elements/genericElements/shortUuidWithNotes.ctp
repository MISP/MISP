<?php
    echo $this->element('genericElements/shortUuid', [
        'uuid' => $uuid
    ]);

    if (!empty($object_type)) {
        $notes = !empty($notes) ? $notes : [];
        $opinions = !empty($opinions) ? $opinions : [];
        $relationships = !empty($relationships) ? $relationships : [];
        $relationshipsInbound = !empty($relationshipsInbound) ? $relationshipsInbound : [];
        echo $this->element('genericElements/Analyst_data/generic', [
            'analyst_data' => ['notes' => $notes, 'opinions' => $opinions, 'relationships_outbound' => $relationships, 'relationships_inbound' => $relationshipsInbound,],
            'object_uuid' => $uuid,
            'object_type' => $object_type
        ]);
    }