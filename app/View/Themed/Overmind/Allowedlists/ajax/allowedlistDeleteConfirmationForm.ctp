<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s allowedlist ?', count($idArray))
    : __('Are you sure you want to delete allowedlist #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Allowedlist Deletion'),
    'model' => 'Allowedlist',
    'url' => $baseurl . '/admin/allowedlists/deleteSelection',
    'message' => $message
]);
?>