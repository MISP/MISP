<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s feeds ?', count($idArray))
    : __('Are you sure you want to delete feed #%s ?', h($idArray[0]));

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Feed Deletion'),
    'model' => 'Feed',
    'url' => $baseurl . '/feeds/deleteSelection',
    'message' => $message
]);
