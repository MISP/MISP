<?php
$disabled = !empty($event['Event']['disable_correlation']);
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Event',
    'url' => $baseurl . '/events/toggleCorrelation/' . h($event['Event']['id']),
    'hiddenField' => false,
    'title' => $disabled ? __('Enable correlation') : __('Disable correlation'),
    'description' => $event['Event']['info'],
    'message' => $disabled
        ? __('Re-enable the correlation for this event. This will automatically re-correlate all contained attributes.')
        : __('This will remove all correlations that already exist for the event and prevent any events to be related via correlations as long as this setting is disabled. Make sure you understand the downsides of disabling correlations.'),
    'submitLabel' => $disabled ? __('Enable correlation') : __('Disable correlation'),
    'submitIcon' => $disabled ? 'link' : 'unlink',
    'accent' => $disabled ? 'primary' : 'warning',
]);
