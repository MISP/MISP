<?php
/*
 * distribution.ctp
 *
 * Expected:
 * $data_path => item.distribution'
 */

$distribution = Hash::extract($row, $field['data_path']);

if (empty($distribution)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/distribution',
    [
        'distribution' => (int)$distribution[0],
        'full' => $isCard
    ]
);

/*
 * "Sharing group" is the only level that does not say who it means, so a
 * caller holding the group can name it here with `sharing_group_path`.
 * Absent for every existing caller.
 */
if (!empty($field['sharing_group_path'])
    && (int)$distribution[0] === 4
) {
    $sharingGroupName = Hash::get($row, $field['sharing_group_path']);
    if (!empty($sharingGroupName)) {
        echo '<div class="text-muted small text-truncate mt-1"'
            . ' title="' . h($sharingGroupName) . '">'
            . h($sharingGroupName) . '</div>';
    }
}