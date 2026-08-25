<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s galaxies ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s galaxy #%s ?', h($actionText), h($idArray[0]));

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Galaxy Toggle'),
    'model' => 'Galaxy',
    'url' => $url,
    'message' => $message
]);
?>
