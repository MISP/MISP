<?php
    $value = Cake\Utility\Hash::extract($data, $field['path'])[0];
    echo $field['mapping'][$value];
