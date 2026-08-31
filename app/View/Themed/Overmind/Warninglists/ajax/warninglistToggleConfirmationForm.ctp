<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s warninglist ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s warninglist #%s ?', h($actionText), h($idArray[0]));

$enabling = !empty($state);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Warninglist Toggle'),
    'model' => 'Warninglist',
    'url' => $url,
    'message' => $message,
    'accent' => $enabling ? 'success' : 'secondary',
    'submitLabel' => ucfirst($actionText),
    'submitIcon' => $enabling ? 'toggle-on' : 'toggle-off',
]);
?>