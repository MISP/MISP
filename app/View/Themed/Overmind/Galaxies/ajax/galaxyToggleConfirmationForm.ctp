<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s galaxies ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s galaxy #%s ?', h($actionText), h($idArray[0]));

// massToggle() sets $state; toggle() does not, so fall back to the verb.
$enabling = isset($state) ? !empty($state) : ($actionText === __('enable'));

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Galaxy Toggle'),
    'model' => 'Galaxy',
    'url' => $url,
    'message' => $message,
    'accent' => $enabling ? 'success' : 'secondary',
    'submitLabel' => ucfirst($actionText),
    'submitIcon' => $enabling ? 'toggle-on' : 'toggle-off',
]);
?>
