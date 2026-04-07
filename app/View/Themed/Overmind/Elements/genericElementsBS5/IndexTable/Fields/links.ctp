<?php
/*
 * links.ctp
 *
 * Expected:
 * $data_path => item.ref'
 */

$links = Hash::extract($row, $field['data_path']);


if (empty($links)) {
    return;
}

echo $this->element(
    'genericElementsBS5/Badges/links',
    [
        'links' => $links,
        'object' => $row,
    ]
);
?>