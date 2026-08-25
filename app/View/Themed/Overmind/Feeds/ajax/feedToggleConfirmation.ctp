<?php
$ids = json_decode($feedList, true) ?: [];
$count = count($ids);
$field = !empty($cache) ? __('caching') : __('pulling');

if (!empty($enable)) {
    $title = __('Enable feeds');
    $message = __n(
        'Enable %s for the selected feed?',
        'Enable %s for the %2$s selected feeds?',
        $count,
        $field,
        $count
    );
    $submitClass = 'btn btn-success';
    $submitIcon = 'play';
} else {
    $title = __('Disable feeds');
    $message = __n(
        'Disable %s for the selected feed?',
        'Disable %s for the %2$s selected feeds?',
        $count,
        $field,
        $count
    );
    $submitClass = 'btn btn-danger';
    $submitIcon = 'stop';
}

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => $title,
    'model' => 'Feed',
    'hiddenField' => false,
    'url' => $this->request->here(false),
    'message' => $message,
    'submitLabel' => !empty($enable) ? __('Enable') : __('Disable'),
    'submitClass' => $submitClass,
    'submitIcon' => $submitIcon,
    'canProceed' => $count > 0,
]);
