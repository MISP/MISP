<?php
/*
 * correlate.ctp
 *
 * Expected:
 * $data_path => item.correlate'
 */
$correlate = Hash::extract($row, $field['data_path']);

if (empty($correlate)) {
    $correlate[0] = false;
}
$boolean = !empty($field['boolean_reverse']) ? !$correlate[0] : $correlate[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Correlation'),
        'false' => __('No correlation'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>