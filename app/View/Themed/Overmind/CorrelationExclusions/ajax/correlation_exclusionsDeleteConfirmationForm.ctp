<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s correlation exclusions ?', count($idArray))
    : __('Are you sure you want to delete correlation exclusion #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('CorrelationExclusion Deletion'),
    'model' => 'CorrelationExclusion',
    'url' => $baseurl . '/correlation_exclusions/deleteSelection',
    'message' => $message
]);
?>