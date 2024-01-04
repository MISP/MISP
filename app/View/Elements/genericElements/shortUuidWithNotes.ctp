<?php

    $uuidHalfWidth = 3;
    $shortUUID = sprintf('%s...%s', substr($uuid, 0, $uuidHalfWidth), substr($uuid, 30-$uuidHalfWidth, $uuidHalfWidth));
    $notes = !empty($notes) ? $notes : [];
    $object_type = !empty($object_type) ? $object_type : null;
    echo sprintf('<span title="%s">%s</span>', $uuid, $shortUUID);
    echo $this->element('genericElements/Analyst_notes/notes', ['notes' => $notes, 'object_uuid' => $uuid, 'object_type' => $object_type]);
