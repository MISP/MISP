<?php
$form = $this->element('genericElements/Form/genericForm', [
    'entity' => null,
    'ajax' => false,
    'raw' => true,
    'data' => [
        'fields' => [
            [
                'type' => 'text',
                'field' => 'ids',
                'default' => !empty($id) ? json_encode([$id]) : ''
            ],
            [
                'type' => 'text',
                'field' => 'tag_list',
            ],
        ],
        'submit' => [
            'action' => $this->request->getParam('action')
        ]
    ]
]);
$formHTML = sprintf('<div class="d-none">%s</div>', $form);
echo $formHTML;
