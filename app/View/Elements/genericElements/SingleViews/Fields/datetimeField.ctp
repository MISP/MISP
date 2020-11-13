<?php
    $value = Hash::extract($data, $field['path'])[0];
    echo date('Y-m-d H:i:s', $value);
