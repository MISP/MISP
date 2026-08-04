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
$boolean = !empty($field['boolean_reverse']) ? !$enabled[0] : $enabled[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>