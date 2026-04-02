<?php
/*
 * version.ctp
 *
 * Expected:
 * $data_path => item.version'
 */

$version = Hash::get($row, $field['data_path']);


echo $this->element(
    'genericElementsBS5/Badges/version',
    [
        'version' => (int)$version,
    ]
);
?>