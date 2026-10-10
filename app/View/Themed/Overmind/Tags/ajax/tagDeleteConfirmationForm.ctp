<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s tags ?', count($idArray))
    : __('Are you sure you want to delete tag #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Tag Deletion'),
    'model' => 'Tag',
    'url' => $baseurl . '/tags/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
?>