<?php
/*
 * proxy.ctp
 *
 * Expected:
 * $data_path => item.skip_proxy'
 */

$proxy = Hash::extract($row, $field['data_path']);

if (empty($proxy)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$proxy[0] : $proxy[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Proxy skipped'),
        'false' => __('Proxy not skipped'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>