<?php
/*
 * Delete confirmation for one galaxy cluster (delete()) or a selection
 * (deleteSelection()). Soft by default, permanent behind the switch, and only
 * permanent when the clusters are already soft-deleted. Forms/delete_mode makes
 * it post in place and refresh the Clusters tab behind it.
 *
 * Expected: $idArray (int[], a selection) or $cluster (the cluster row); $hard
 * (bool); $countedIds (int[], the live clusters the Clusters tab counts);
 * $ownPage (bool, opened from the cluster's own page)
 */
$isMass = isset($idArray) && is_array($idArray);
$ids = $isMass ? array_values(array_map('intval', $idArray)) : [(int)$cluster['id']];
$count = count($ids);
$hard = !empty($hard);

if ($isMass) {
    $message = $hard
        ? __n('Permanently delete this galaxy cluster?', 'Permanently delete these %s galaxy clusters?', $count, $count)
        : __n('Delete this galaxy cluster?', 'Delete these %s galaxy clusters?', $count, $count);
} else {
    $message = sprintf(
        $hard ? __('Permanently delete the galaxy cluster %s?') : __('Delete the galaxy cluster %s?'),
        '<strong>' . h($cluster['value']) . '</strong>'
    );
}

$hardHint = __('It is removed for good and its UUID is blocklisted, so it is not created again. A default cluster comes back when the galaxies are force-updated.');

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'GalaxyCluster',
    'url' => $isMass
        ? $baseurl . '/galaxy_clusters/deleteSelection'
        : $baseurl . '/galaxy_clusters/delete/' . $ids[0],
    'hiddenField' => false,
    'eyebrow' => __('Galaxy clusters'),
    'accent' => 'danger',
    'title' => __n('Delete galaxy cluster', 'Delete %s galaxy clusters', $count, $count),
    'message' => $message,
    'escape' => false,
    'warning' => $hard ? h($hardHint) : null,
    'bodyHtml' => $this->element('genericElementsBS5/Forms/delete_mode', [
        'model' => 'GalaxyCluster',
        'ids' => $ids,
        'inUrl' => !$isMass,
        'hard' => $hard,
        'softHint' => __('Left off, it is soft-deleted: the deletion is shared with other instances and the cluster can be restored later.'),
        'hardHint' => $hardHint,
        'countTab' => 'clusters',
        'counted' => $countedIds ?? [],
        'ownPage' => !empty($ownPage),
        'parentUrl' => $isMass ? null : $baseurl . '/galaxies/view/' . (int)$cluster['galaxy_id'],
    ]),
    'submitLabel' => $hard ? __('Delete permanently') : __('Delete'),
    'submitIcon' => 'trash',
    'meta' => $isMass ? [] : [['label' => __('Cluster'), 'id' => $ids[0]]],
]);
