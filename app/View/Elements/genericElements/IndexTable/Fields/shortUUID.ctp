<?php
    $uuid = Hash::get($row, $field['data_path']);
    if (empty($uuid) || empty($field['object_type'])) {
        throw new MethodNotAllowedException(__('No UUID or object_type provided'), 500);
        
    }
    echo $this->element('genericElements/shortUuid', ['uuid' => $uuid]);