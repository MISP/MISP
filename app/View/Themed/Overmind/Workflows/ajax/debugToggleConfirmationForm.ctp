<?php
$enabling = $actionText === 'enable';
$debugUrl = Configure::read('Plugin.Workflow_debug_url');

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('Workflow Debug Mode'),
    'model' => 'Workflow',
    'url' => $url,
    'message' => __(
        'Are you sure you want to %s debug mode for the workflow `%s` ?',
        h($actionText),
        h($workflow['Workflow']['name'])
    ),
    'hiddenField' => false,
    'warning' => ($enabling && empty($debugUrl))
        ? __('Plugin.Workflow_debug_url is not set — nodes will have nowhere to send their debug data.')
        : null,
    'submitLabel' => $enabling ? __('Enable') : __('Disable'),
    'submitClass' => $enabling ? 'btn btn-warning' : 'btn btn-secondary',
    'submitIcon' => 'bug',
]);
?>
