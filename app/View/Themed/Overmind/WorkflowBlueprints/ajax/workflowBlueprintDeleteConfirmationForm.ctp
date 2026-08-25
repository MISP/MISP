<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s workflow blueprints ?', count($idArray))
    : __('Are you sure you want to delete workflow blueprint #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Workflow Blueprint Deletion'),
    'model' => 'WorkflowBlueprint',
    'url' => $baseurl . '/workflowBlueprints/deleteSelection',
    'message' => $message
]);
?>
