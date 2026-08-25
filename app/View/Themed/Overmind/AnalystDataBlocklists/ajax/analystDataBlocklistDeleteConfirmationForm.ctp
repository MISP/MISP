<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s analyst data blocklist entries ?', count($idArray))
    : __('Are you sure you want to delete analyst data blocklist entry #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => __('Analyst Data Blocklist Deletion'),
    'model' => 'AnalystDataBlocklist',
    'url' => $baseurl . '/analyst_data_blocklists/deleteSelection',
    'message' => $message
]);
?>
