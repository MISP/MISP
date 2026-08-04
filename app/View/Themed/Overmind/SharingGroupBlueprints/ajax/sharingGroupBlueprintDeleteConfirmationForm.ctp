<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s SharingGroup Blueprints ?', count($idArray))
    : __('Are you sure you want to delete SharingGroup Blueprint #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('SharingGroupBlueprint Deletion'),
    'model' => 'SharingGroupBlueprint',
    'url' => $baseurl . '/SharingGroupBlueprints/deleteSelection',
    'message' => $message
]);
?>