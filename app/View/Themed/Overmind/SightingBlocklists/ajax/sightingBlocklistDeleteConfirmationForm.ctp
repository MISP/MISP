<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s sighting blocklist entries ?', count($idArray))
    : __('Are you sure you want to delete sighting blocklist entry #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Sighting Blocklist Deletion'),
    'model' => 'SightingBlocklist',
    'url' => $baseurl . '/sightingBlocklists/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
?>
