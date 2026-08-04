<?php

$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'templates',
    'menuItem' => $edit ? 'edit' : 'add'
]);

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => $edit ? __('Edit Template') : __('Create Template'),
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
                'selectedTags' => isset($currentTags) ? $currentTags : [],
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
