<?php
    $uuid = Hash::extract($data, $field['path'])[0];
    echo sprintf(
        '<span class="quickSelect">%s</span>',
        h($uuid)
    );

    echo $this->element('genericElements/Analyst_notes/notes');
    if (!empty($notes)) {
        echo $this->element('genericElements/Analyst_notes/notes', ['notes' => $notes, 'object_uuid' => $object_uuid, 'object_type' => $object_type]);
    }
