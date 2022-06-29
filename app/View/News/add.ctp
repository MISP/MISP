<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
echo $this->element(
    '/genericElements/SideMenu/side_menu',
    [
        'menuList' => 'news',
        'menuItem' => $edit ? 'edit' : 'add'
    ]
);

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => $edit ? __('Edit News Item') : __('Add News Item'),
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
                'label' => __('Message'),
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
