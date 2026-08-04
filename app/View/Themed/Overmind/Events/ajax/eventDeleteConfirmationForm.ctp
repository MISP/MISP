<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s events ?', count($idArray))
    : __('Are you sure you want to delete event #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Event Deletion'),
    'model' => 'Event',
    'url' => $baseurl . '/events/delete',
    'message' => $message
]);
?>