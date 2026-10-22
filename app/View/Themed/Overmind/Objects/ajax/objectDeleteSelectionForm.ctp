<?php
/*
 * Delete confirmation for the object index's mass select. Soft by default,
 * permanent behind the switch, and only permanent when the objects are already
 * soft-deleted. Forms/delete_mode makes it post in place and refresh the index
 * behind it.
 *
 * Expected: $idArray (int[]), $hard (bool)
 */
$ids = array_values(array_map('intval', $idArray));
$count = count($ids);
$hard = !empty($hard);

if ($hard) {
    $message = __n(
        'Permanently delete this object and its attributes?',
        'Permanently delete these %s objects and their attributes?',
        $count, $count
    );
} else {
    $message = __n(
        'Delete this object and its attributes?',
        'Delete these %s objects and their attributes?',
        $count, $count
    );
}

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Object',
    'url' => $baseurl . '/objects/deleteSelection',
    'hiddenField' => false,
    'eyebrow' => __('Objects'),
    'accent' => 'danger',
    'title' => __n('Delete object', 'Delete %s objects', $count, $count),
    'message' => $message,
    'warning' => $hard ? __('It is removed for good. This cannot be undone.') : null,
    'bodyHtml' => $this->element('genericElementsBS5/Forms/delete_mode', [
        'model' => 'Object',
        'ids' => $ids,
        'hard' => $hard,
    ]),
    'submitLabel' => $hard ? __('Delete permanently') : __('Delete'),
    'submitIcon' => 'trash',
]);
