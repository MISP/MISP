<?php
/*
 * type.ctp
 *
 * Expected:
 * $data_path => item.type'
 */

$type = Hash::extract($row, $field['data_path']);

if (empty($type)) {
    return;
}

echo $this->element(
    'genericElementsBS5/Badges/type',
    [
        'type' => $type[0],
    ]
);
?>
