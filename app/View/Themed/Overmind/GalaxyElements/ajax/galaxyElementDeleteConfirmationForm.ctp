<?php
$count = count($idArray);
$message = $count > 1
    ? __('Are you sure you want to delete these %s galaxy elements?', $count)
    : __('Are you sure you want to delete this galaxy element?');

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Delete Galaxy Element'),
    'model' => 'GalaxyElement',
    'url' => $baseurl . '/galaxy_elements/deleteSelection',
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
