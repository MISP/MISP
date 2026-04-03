<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s collections ?', count($idArray))
    : __('Are you sure you want to delete collection #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Collection Deletion'),
    'model' => 'Collection',
    'url' => $baseurl . '/collections/deleteSelection',
    'message' => $message
]);
?>