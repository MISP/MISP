<?php
/*
 * highlighted.ctp
 *
 * Expected:
 * $data_path => item.highlighted'
 */

$highlighted = Hash::extract($row, $field['data_path']);

if (empty($highlighted)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $highlighted[0],
        'full' => $isCard,
        'true' => __('Highlighted'),
        'false' => __('Not Highlighted'),
        'trueColor'  => 'success',
        'falseColor' => 'muted',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>