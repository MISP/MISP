<?php
/*
 * local.ctp
 *
 * Expected:
 * $data_path => item.local'
 */

$local = Hash::extract($row, $field['data_path']);

if (empty($local)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $local[0],
        'full' => $isCard,
        'true' => __('Local only'),
        'false' => __('Global'),
        'trueColor'  => 'tag',
        'falseColor' => 'galaxy',
        'trueIcon'   => 'fa-user',
        'falseIcon'  => 'fa-globe'
    ]
);
?>