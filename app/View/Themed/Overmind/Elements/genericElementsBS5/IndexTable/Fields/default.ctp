<?php
/*
 * distribution.ctp
 *
 * Expected:
 * $data_path => item.distribution'
 */

$default = Hash::extract($row, $field['data_path']);

if (empty($default)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/default',
    [
        'default' => $default[0],
        'full' => $isCard
    ]
);
?>