<?php
/*
 * shared.ctp
 *
 * Expected:
 * $data_path => item.share'
 */

$shared = Hash::extract($row, $field['data_path']);

if (empty($shared)) {
    return;
}
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $shared[0],
        'full' => $isCard,
        'true' => __('Shared'),
        'false' => __('Not shared'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>