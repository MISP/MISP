<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s object templates ?', count($idArray))
    : __('Are you sure you want to delete object template #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('ObjectTemplate Deletion'),
    'model' => 'ObjectTemplate',
    'url' => $baseurl . '/objectTemplates/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
?>