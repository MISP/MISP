<?php
/*
 * count.ctp
 *
 * Expected:
 * $data_path => item.count'
 */

$count = Hash::extract($row, $field['data_path']);

if (empty($count)) {
    return;
}

echo $this->element(
    'genericElementsBS5/Badges/count',
    [
        'count' => $count[0],
    ]
);
?>