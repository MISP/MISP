<?php
$isEdit = $this->request->params['action'] === 'edit';
echo $this->element(
    '/genericElements/SideMenu/side_menu',
    [
        'menuList' => 'news',
        'menuItem' => $isEdit ? 'edit' : 'add'
    ]
);

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => $isEdit ? __('Edit News Item') : __('Add News Item'),
        'fields' => [
            [
                'field' => 'title',
                'label' => __('Title'),
                'type' => 'text',
                'error' => ['escape' => false],
                'div' => 'input clear',
                'class' => 'input-xxlarge',
            ],
            [
                'field' => 'message',
                'label' => __('Message (you can use Markdown format)'),
                'type' => 'textarea',
                'error' => ['escape' => false],
                'div' => 'input clear',
                'class' => 'input-xxlarge'
            ],
            [
                'field' => 'anonymise',
                'label' => __('Create anonymously'),
                'type' => 'checkbox',
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
