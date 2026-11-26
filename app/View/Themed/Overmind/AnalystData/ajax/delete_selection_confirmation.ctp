<?php
$count = count($idArray);
$message = $count > 1
    ? __('Are you sure you want to delete these %s %ss? This action cannot be undone.', $count, strtolower($adType))
    : __('Are you sure you want to delete this %s? This action cannot be undone.', strtolower($adType));

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title'   => __('Delete %s', $count > 1 ? Inflector::pluralize($adType) : $adType),
    'model'   => $adType,
    'url'     => $baseurl . '/analystData/deleteSelection/' . $adType,
    'message' => $message,
    'accent' => 'danger',
    'submitLabel' => __('Delete'),
    'submitIcon' => 'trash',
]);
