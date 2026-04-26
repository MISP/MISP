<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s tag collections ?', count($idArray))
    : __('Are you sure you want to delete tag collection #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Collection Deletion'),
    'model' => 'TagCollection',
    'url' => $baseurl . '/tagCollections/deleteSelection',
    'message' => $message
]);
?>