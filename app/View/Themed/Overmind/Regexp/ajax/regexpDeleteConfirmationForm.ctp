<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s regexp ?', count($idArray))
    : __('Are you sure you want to delete regexp #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Regexp Deletion'),
    'model' => 'Regexp',
    'url' => $baseurl . '/admin/regexp/deleteSelection',
    'message' => $message
]);
?>