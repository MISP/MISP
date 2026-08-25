<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s organisation blocklist entries ?', count($idArray))
    : __('Are you sure you want to delete organisation blocklist entry #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Organisation Blocklist Deletion'),
    'model' => 'OrgBlocklist',
    'url' => $baseurl . '/orgBlocklists/deleteSelection',
    'message' => $message
]);
?>
