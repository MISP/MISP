<?php
/*
 * vetted.ctp
 *
 * Expected:
 * $data_path => item.vetted'
 */

$vetted = Hash::extract($row, $field['data_path']);

if (empty($vetted)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$vetted[0] : $vetted[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Vetted'),
        'false' => __('Not vetted'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>