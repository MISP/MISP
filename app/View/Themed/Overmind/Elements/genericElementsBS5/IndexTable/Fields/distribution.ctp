<?php
/*
 * distribution.ctp
 *
 * Expected:
 * $data_path => item.distribution'
 */

$distribution = Hash::extract($row, $field['data_path']);

if (empty($distribution)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/distribution',
    [
        'distribution' => (int)$distribution[0],
        'full' => $isCard
    ]
);