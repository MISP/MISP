<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s ObjectRelationship ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s ObjectRelationship #%s ?', h($actionText), h($idArray[0]));

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('ObjectRelationship Toggle'),
    'model' => 'ObjectRelationship',
    'url' => $url,
    'message' => $message
]);
?>