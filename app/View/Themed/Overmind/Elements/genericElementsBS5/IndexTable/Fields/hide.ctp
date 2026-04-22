<?php
/*
 * hide.ctp
 *
 * Expected:
 * $data_path => item.hide_(object)'
 */

$hide = Hash::extract($row, $field['data_path']);

if (empty($hide)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $hide[0],
        'full' => $isCard,
        'true' => __('Hidden'),
        'false' => __('Visible'),
        'trueColor'  => 'warning',
        'falseColor' => 'success',
        'trueIcon'   => 'fa-eye-slash',
        'falseIcon'  => 'fa-eye'
    ]
);
?>