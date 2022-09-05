<?php
    $value = Hash::extract($data, $field['path'])[0];
    echo $field['mapping'][$value];
