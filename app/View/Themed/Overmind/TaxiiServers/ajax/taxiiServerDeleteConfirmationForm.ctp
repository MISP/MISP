<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s taxiiServers ?', count($idArray))
    : __('Are you sure you want to delete taxiiServer #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('TaxiiServer Deletion'),
    'model' => 'TaxiiServer',
    'url' => $baseurl . '/taxiiServers/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
?>