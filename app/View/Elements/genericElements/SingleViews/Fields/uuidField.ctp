<?php
    $uuid = Hash::extract($data, $field['path'])[0];
    echo sprintf(
        '<span class="quickSelect">%s</span>',
        h($uuid)
    );

    $notes = !empty($notes) ? $notes : [];
    $object_uuid = !empty($object_uuid) ? $object_uuid : null;
    $object_type = !empty($object_type) ? $object_type : null;
    echo $this->element('genericElements/Analyst_notes/notes', ['notes' => $notes, 'object_uuid' => $object_uuid, 'object_type' => $object_type]);
