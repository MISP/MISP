<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s warninglists ?', count($idArray))
    : __('Are you sure you want to delete warninglist #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Warninglist Deletion'),
    'model' => 'Warninglist',
    'url' => $baseurl . '/warninglists/deleteSelection',
    'message' => $message
]);
?>