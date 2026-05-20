<?php
/*
 * ssl.ctp
 *
 * Expected:
 * $data_path => item.skip_ssl'
 */

$ssl = Hash::extract($row, $field['data_path']);

if (empty($ssl)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$ssl[0] : $ssl[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('SSL skipped'),
        'false' => __('SSL not skipped'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>