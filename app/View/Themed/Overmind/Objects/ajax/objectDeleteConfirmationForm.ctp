<?php
/*
 * Delete confirmation for a single object, from its row or card. The caller
 * decides soft vs permanent from the object's own state (`/true` on an object
 * already soft-deleted), so the switch is only offered for a live one.
 *
 * Expected: $id (int), $hard (bool)
 */
$objectId = (int)($id ?? 0);
$hard = !empty($hard);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Object',
    'url' => $baseurl . '/objects/delete/' . $objectId,
    'hiddenField' => false,
    'eyebrow' => __('Objects'),
    'accent' => 'danger',
    'title' => __('Delete object'),
    'message' => $hard
        ? __('Permanently delete this object and its attributes?')
        : __('Delete this object and its attributes?'),
    'warning' => $hard ? __('It is removed for good. This cannot be undone.') : null,
    'bodyHtml' => $this->element('genericElementsBS5/Forms/delete_mode', [
        'model' => 'Object',
        'ids' => [$objectId],
        'inUrl' => true,
        'hard' => $hard,
    ]),
    'submitLabel' => $hard ? __('Delete permanently') : __('Delete'),
    'submitIcon' => 'trash',
    'meta' => [['label' => __('Object'), 'id' => $objectId]],
]);
