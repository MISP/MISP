<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s sightingdbs ?', count($idArray))
    : __('Are you sure you want to delete sightingdb #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Sightingdb Deletion'),
    'model' => 'Sightingdb',
    'url' => $baseurl . '/sightingdb/deleteSelection',
    'message' => $message
]);
?>