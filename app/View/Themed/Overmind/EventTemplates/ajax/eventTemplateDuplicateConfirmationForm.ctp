<?php

$templateName = $template['name'] ?? '';
$copyName = sprintf('%s %s', $templateName, __('(copy)'));

echo $this->element('genericElementsBS5/Forms/confirmationForm', [
    'title' => __('Duplicate Event Template'),
    'model' => 'EventTemplate',
    'hiddenField' => false,
    'url' => $baseurl . '/event_templates/duplicate/' . (int)$id,
    'message' => __('Create a copy of "%s"?', $templateName),
    'warning' => __(
        'The copy is saved as "%s", owned by your organisation, visible to it only, and active. It is a fork: library updates will not touch it.',
        $copyName
    ),
    'submitLabel' => __('Duplicate'),
    'submitIcon' => 'copy',
]);
