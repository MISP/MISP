<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s taxonomies ?', count($idArray))
    : __('Are you sure you want to delete taxonomy #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Taxonomy Deletion'),
    'model' => 'Taxonomy',
    'url' => $baseurl . '/taxonomies/deleteSelection',
    'message' => $message
]);
?>