<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s elements ?', count($idArray))
    : __('Are you sure you want to delete element #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Element Deletion'),
    'model' => 'CollectionElement',
    'url' => $baseurl . '/collectionElements/deleteSelection',
    'message' => $message
]);
?>