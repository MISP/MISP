<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s these %s %s ?', h($actionText), count($idArray), h($itemLabelPlural))
    : __('Are you sure you want to %s the %s `%s` ?', h($actionText), h($itemLabel), h($idArray[0]));

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('%s %s', ucfirst($actionText), h($itemLabelPlural)),
    'model' => 'Workflow',
    'url' => $url,
    'message' => $message,
    // The ids already travel in the POST URL.
    'hiddenField' => false,
    'submitLabel' => ucfirst($actionText),
    'submitClass' => $actionText === 'enable' ? 'btn btn-success' : 'btn btn-danger',
    'submitIcon' => $actionText === 'enable' ? 'play' : 'stop',
]);
