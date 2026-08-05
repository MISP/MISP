<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s event blocklist entries ?', count($idArray))
    : __('Are you sure you want to delete event blocklist entry #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Event Blocklist Deletion'),
    'model' => 'EventBlocklist',
    'url' => $baseurl . '/eventBlocklists/deleteSelection',
    'message' => $message
]);
?>
