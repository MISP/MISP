<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s galaxies ?', count($idArray))
    : __('Are you sure you want to delete galaxy #%s ?', h($idArray[0]));

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Galaxy Deletion'),
    'model' => 'Galaxy',
    'url' => $baseurl . '/galaxies/deleteSelection',
    'message' => $message
]);
?>
