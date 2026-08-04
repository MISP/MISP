<?php
/*
 * multiple.ctp
 *
 * Expected:
 * $data_path => item.multiple'
 */

$multiple = Hash::extract($row, $field['data_path']);

if (empty($multiple)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$multiple[0] : $multiple[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Multiple'),
        'false' => __('Single'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>