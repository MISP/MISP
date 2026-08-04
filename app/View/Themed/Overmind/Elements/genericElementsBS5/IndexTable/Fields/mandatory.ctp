<?php
/*
 * mandatory.ctp
 *
 * Expected:
 * $data_path => item.mandatory'
 */

$mandatory = Hash::extract($row, $field['data_path']);

if (empty($mandatory)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$mandatory[0] : $mandatory[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Mandatory'),
        'false' => __('Not mandatory'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>