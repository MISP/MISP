<?php
/*
 * pull.ctp
 *
 * Expected:
 * $data_path => item.pull'
 */

$pull = Hash::extract($row, $field['data_path']);

if (empty($pull)) {
    return;
}
$boolean = !empty($field['boolean_reverse']) ? !$pull[0] : $pull[0];
$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $boolean,
        'full' => $isCard,
        'true' => __('Pulled'),
        'false' => __('Not pulled'),
        'trueColor'  => 'success',
        'falseColor' => 'danger',
        'trueIcon'   => 'fa-check-circle',
        'falseIcon'  => 'fa-times-circle'
    ]
);
?>