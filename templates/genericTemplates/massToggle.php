<?php

$confirmMessage = __('Are you sure you want to toggle the field `{0}` for all the {1} selected elements?', h($fieldName), count($ids));
$form = $this->element('genericElements/Form/genericForm', [
    'entity' => null,
    'ajax' => false,
    'raw' => true,
    'data' => [
        'fields' => [
            [
                'type' => 'text',
                'field' => 'ids',
                'default' => !empty($id) ? json_encode([$ids]) : ''
            ]
        ],
        'submit' => [
            'action' => $this->request->getParam('action')
        ]
    ]
]);
$formHTML = sprintf('<div class="d-none">%s</div>', $form);
$bodyHTML = $formHTML;

$entityTable = $this->Bootstrap->table(
    ['hover' => false, 'bordered' => false, 'borderless' => !true,],
    [
        'items' => array_map(fn ($entity) => $entity->toArray(), $entities),
        'fields' => $tableFields,
    ]
);

$bodyHTML .= $entityTable;

$modalOptions = [
    'size' => 'lg',
    'titleHtml' => $confirmMessage,
    'type' => 'confirm',
    'bodyHtml' => $bodyHTML,
];

echo $this->Bootstrap->modal($modalOptions);
