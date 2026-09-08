<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s cerebrates ?', count($idArray))
    : __('Are you sure you want to delete cerebrate #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Cerebrate Deletion'),
    'model' => 'Cerebrate',
    'url' => $baseurl . '/cerebrates/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
?>