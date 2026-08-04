<?php
/*
 * batch.ctp
 *
 * Expected:
 * $data_path => item.batch'
 */

$batch = Hash::extract($row, $field['data_path']);

if (empty($batch)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$batch[0] : $batch[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Batch'),
        'false' => __('Not batch'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>