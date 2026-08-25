<?php
/**
 * Delete confirmation modal for one or many auth keys.
 */
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s auth keys?', count($idArray))
    : __('Are you sure you want to delete auth key #%s?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Auth key deletion'),
    'model' => 'AuthKey',
    'url' => $baseurl . '/auth_keys/deleteSelection',
    'message' => $message,
]);
