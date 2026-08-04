<?php
/*
 * blueprint_sharing_group.ctp
 *
 */

$sgId = Hash::get($row, 'SharingGroupBlueprint.sharing_group_id');
$sgData = Hash::get($row, 'SharingGroup');
$blueprintId = Hash::get($row, 'SharingGroupBlueprint.id');

if (empty($sgId) || empty(array_filter($sgData))) {
    echo '<span class="text-muted fst-italic small">' . __('None') . '</span>';
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/blueprint_sharing_group',
    [
        'sgData' => $sgData,
        'blueprintId'=> (int)$blueprintId,
        'full' => $isCard
    ]
);