<?php
echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title'   => __('Delete %s', $adType),
    'model'   => $adType,
    'url'     => $baseurl . '/analystData/delete/' . $adType . '/' . $adId,
    'message' => __('Are you sure you want to delete this %s? This action cannot be undone.', strtolower($adType)),
]);
