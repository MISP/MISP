<?php
/*
 * exportable.ctp
 *
 * Expected:
 * $data_path => item.exportable'
 */

$exportable = Hash::extract($row, $field['data_path']);

if (empty($exportable)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $exportable[0],
        'full' => $isCard,
        'true' => __('Exportable'),
        'false' => __('Not Exportable'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>