<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s warninglist ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s warninglist #%s ?', h($actionText), h($idArray[0]));

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Warninglist Toggle'),
    'model' => 'Warninglist',
    'url' => $url,
    'message' => $message
]);
?>