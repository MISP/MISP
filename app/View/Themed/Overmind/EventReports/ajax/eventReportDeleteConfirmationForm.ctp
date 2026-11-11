<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s event reports ?', count($idArray))
    : __('Are you sure you want to delete event report #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Event Report Deletion'),
    'model' => 'EventReport',
    'url' => $baseurl . '/event_reports/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
?>