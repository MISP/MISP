<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s object relationships ?', count($idArray))
    : __('Are you sure you want to delete object relationship #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('ObjectRelationship Deletion'),
    'model' => 'ObjectRelationship',
    'url' => $baseurl . '/object_relationships/deleteSelection',
    'message' => $message
]);
?>