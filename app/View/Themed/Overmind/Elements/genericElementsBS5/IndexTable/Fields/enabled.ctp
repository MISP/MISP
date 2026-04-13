<?php
/*
 * enabled.ctp
 *
 * Expected:
 * $data_path => item.enabled'
 */

$enabled = Hash::extract($row, $field['data_path']);

if (empty($enabled)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/enabled',
    [
        'enabled' => $enabled[0],
        'full' => $isCard
    ]
);
?>