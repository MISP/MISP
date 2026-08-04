<?php
/*
 * type.ctp
 *
 * Expected:
 * $data_path => item.type'
 */

$type = Hash::extract($row, $field['data_path']);

if (empty($type) || $type[0] === "") {
    return;
}

echo $this->element(
    'genericElementsBS5/Badges/type',
    [
        'type' => $type[0],
    ]
);
?>
