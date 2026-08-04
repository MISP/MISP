<?php
/*
 * required.ctp
 *
 * Expected:
 * $data_path => item.required'
 */

$required = Hash::extract($row, $field['data_path']);

if (empty($required)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $required[0],
        'full' => $isCard,
        'true' => __('Required'),
        'false' => __('Not required'),
        'trueColor'  => 'success',
        'falseColor' => 'muted',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>