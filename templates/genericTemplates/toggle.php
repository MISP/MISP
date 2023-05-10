<?php

$form = $this->Form->postLink(__('Toggle'), ['action' => 'toggle', $entity->id, $fieldName], ['confirm' => __('Are you sure you want to toggle `{0}` of {1}?', h($fieldName), h($entity->id))]);
$formHTML = sprintf('<div class="d-none">%s</div>', $form);
$bodyHTML = $formHTML;

$modalOptions = [
    'title' => __('Are you sure you want to toggle `{0}` of {1}?', h($fieldName), h($entity->id)),
    'type' => 'confirm',
    'bodyHtml' => $bodyHTML,
];

echo $this->Bootstrap->modal($modalOptions);
