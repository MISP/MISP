<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s servers ?', count($idArray))
    : __('Are you sure you want to delete server #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Server Deletion'),
    'model' => 'Server',
    'url' => $baseurl . '/servers/deleteSelection',
    'message' => $message
]);
?>