<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s SharingGroups ?', count($idArray))
    : __('Are you sure you want to delete SharingGroup #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('SharingGroup Deletion'),
    'model' => 'SharingGroup',
    'url' => $baseurl . '/SharingGroups/deleteSelection',
    'message' => $message
]);
?>