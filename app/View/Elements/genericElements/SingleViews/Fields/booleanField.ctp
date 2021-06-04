<?php
$value = Hash::extract($data, $field['path'])[0];
$mapping = !empty($field['mapping']) ? $field['mapping'] : [
    false => '<i class="fas fa-times"></i>',
    true => '<i class="fas fa-check"></i>'
];
echo $mapping[(bool)$value];
