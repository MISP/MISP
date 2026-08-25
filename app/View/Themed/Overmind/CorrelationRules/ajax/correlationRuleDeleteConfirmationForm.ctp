<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s correlation rules ?', count($idArray))
    : __('Are you sure you want to delete correlation rule #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Correlation Rule Deletion'),
    'model' => 'CorrelationRule',
    'url' => $baseurl . '/correlationRules/deleteSelection',
    'message' => $message
]);
?>
