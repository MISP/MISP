<?php
/**
 * Supported parameters:
 * - title: The title of the modal
 * - question: The content of the modal's body.
 * - actionName: The text of the confirm button. Basically what the confirmation will do
 * - modalOptions: Additional options to be passed to the modal
 */

$form = $this->element('genericElements/Form/genericForm', [
    'entity' => null,
    'ajax' => false,
    'raw' => true,
    'data' => [
        'fields' => [
        ],
        'submit' => [
            'action' => $this->request->getParam('action')
        ]
    ]
]);
$formHTML = sprintf('<div class="d-none">%s</div>', $form);
$bodyMessage = h($question ?? '');
$bodyHTML = sprintf('%s%s', $formHTML, $bodyMessage);

$defaultOptions = [
    'size' => 'lg',
    'title' => isset($title) ? h($title) : __('Confirm'),
    'type' => 'confirm',
    'confirmButton' => [
        'text' => !empty($actionName) ? h($actionName) : __('Confirm'),
        'variant' => 'primary',
    ],
];
$modalOptions = array_merge($defaultOptions, $modalOptions ?? []);
$modalOptions['bodyHtml'] = $bodyHTML;

echo $this->Bootstrap->modal($modalOptions);
