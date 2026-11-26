<?php
/*
 * Delete confirmation for one attribute (delete()) or a selection
 * (deleteSelection()). Soft by default, permanent behind the switch, and only
 * permanent when the rows are already soft-deleted. Forms/delete_mode makes it
 * post in place and refresh the index behind it.
 *
 * Expected: $idArray (int[], a selection) or $id (int); $hard (bool);
 * $countedIds (int[], the live standalone rows the Attributes tab counts)
 */
$isMass = isset($idArray) && is_array($idArray);
$ids = $isMass ? array_values(array_map('intval', $idArray)) : [(int)$id];
$count = count($ids);
$hard = !empty($hard);

if ($hard) {
    $message = __n(
        'Permanently delete this attribute?',
        'Permanently delete these %s attributes?',
        $count, $count
    );
} else {
    $message = __n(
        'Delete this attribute?',
        'Delete these %s attributes?',
        $count, $count
    );
}

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Attribute',
    'url' => $isMass
        ? $baseurl . '/attributes/deleteSelection'
        : $baseurl . '/attributes/delete/' . $ids[0],
    'hiddenField' => false,
    'eyebrow' => __('Attributes'),
    'accent' => 'danger',
    'title' => __n('Delete attribute', 'Delete %s attributes', $count, $count),
    'message' => $message,
    'warning' => $hard ? __('It is removed for good. This cannot be undone.') : null,
    'bodyHtml' => $this->element('genericElementsBS5/Forms/delete_mode', [
        'model' => 'Attribute',
        'ids' => $ids,
        'inUrl' => !$isMass,
        'hard' => $hard,
        'countTab' => 'attributes',
        'counted' => $countedIds ?? [],
    ]),
    'submitLabel' => $hard ? __('Delete permanently') : __('Delete'),
    'submitIcon' => 'trash',
    'meta' => $isMass ? [] : [['label' => __('Attribute'), 'id' => $ids[0]]],
]);
