<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s bookmarks ?', count($idArray))
    : __('Are you sure you want to delete bookmark #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Bookmark Deletion'),
    'model' => 'Bookmark',
    'url' => $baseurl . '/bookmarks/deleteSelection',
    'message' => $message
]);
?>
