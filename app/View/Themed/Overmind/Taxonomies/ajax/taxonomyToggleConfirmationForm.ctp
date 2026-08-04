<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s taxonomies ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s taxonomy #%s ?', h($actionText), h($idArray[0]));

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Taxonomy Toggle'),
    'model' => 'Taxonomy',
    'url' => $url,
    'message' => $message
]);
?>