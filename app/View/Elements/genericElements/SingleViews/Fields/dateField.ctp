<?php
    $value = Hash::extract($data, $field['path'])[0];
    if (empty($value)) {
        echo 'N/A';
    } else {
        echo date('Y-m-d', $value);
    }
