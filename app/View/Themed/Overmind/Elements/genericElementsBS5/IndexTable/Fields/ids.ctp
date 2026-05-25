<?php
/*
 * ids.ctp
 *
 * Expected:
 * $data_path => item.ids'
 */

$ids = Hash::extract($row, $field['data_path']);

if (empty($ids)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$ids[0] : $ids[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('IDS'),
        'false' => __('Not to IDS'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>