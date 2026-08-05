<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s variables ?', count($idArray))
    : __('Are you sure you want to delete variable #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Variable Deletion'),
    'model' => 'EventReportTemplateVariable',
    'url' => $baseurl . '/EventReportTemplateVariables/deleteSelection',
    'message' => $message
]);
?>