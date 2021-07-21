<?php
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'templates', 'menuItem' => 'add'));

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => __('Create Template'),
        'fields' => [
            [
                'field' => 'name',
                'label' => __('Name'),
            ],
            [
                'field' => 'tags',
                'label' => __('Tags'),
                'type' => 'tags',
                'tags' => $tags,
                'tagInfo' => $tagInfo
            ],
            [
                'field' => 'description',
                'label' => __('Template Description'),
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'span6',
                'placeholder' => __('A description of the template')
            ],
            [
                'field' => 'share',
                'label' => __('Share this template with others'),
                'type' => 'checkbox'
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
