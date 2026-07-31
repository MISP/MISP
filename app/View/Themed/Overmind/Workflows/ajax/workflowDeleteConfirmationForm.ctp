<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s workflows ?', count($idArray))
    : __('Are you sure you want to delete workflow #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Workflow Deletion'),
    'model' => 'Workflow',
    'url' => $baseurl . '/workflows/deleteSelection',
    'message' => $message
]);
?>
