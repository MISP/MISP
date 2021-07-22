<?php

$this->set('menuData', ['menuList' => 'templates', 'menuItem' => 'view',  'mayModify' => $mayModify]);

echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Template',
        'data' => $template,
        'fields' => [
            [
                'key' => __('Id'),
                'path' => 'Template.id'
            ],
            [
                'key' => __('Name'),
                'path' => 'Template.name'
            ],
            [
                'key' => __('Description'),
                'path' => 'Template.description'
            ],
            [
                'key' => __('Tags'),
                'path' => 'TemplateTag',
                'type' => 'tags'
            ],
            [
                'key' => __('Organisation'),
                'path' => 'Template.org',
            ],
            [
                'key' => __('Shareable'),
                'path' => 'Template.share',
                'type' => 'boolean'
            ]
        ]
    ]
);

echo $this->element('templateElements/templateElements', ['templateId' => $template['Template']['id']]);
