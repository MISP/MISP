<?php
/*
 * all_orgs.ctp
 *
 * Expected:
 * $data_path => item.all_orgs'
 */

$all_orgs = Hash::extract($row, $field['data_path']);

if (empty($all_orgs)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/boolean',
    [
        'boolean' => $all_orgs[0],
        'full' => $isCard,
        'true' => __('All orgs'),
        'false' => __('Restricted to the creator org'),
        'trueColor'  => 'success',
        'falseColor' => 'muted',
        'trueIcon'   => 'fa-lock-open',
        'falseIcon'  => 'fa-lock'
    ]
);
?>