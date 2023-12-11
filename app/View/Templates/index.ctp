<?php

$this->set('menuData', ['menuList' => 'templates', 'menuItem' => 'index']);

foreach ($list as &$item) {
    $item['Organisation'] = ['name' => $item['Template']['org']];
}

echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'title' => empty($ajax) ? __('Templates') : false,
            'data' => $list,
            'fields' => [
                [
                    'name' => 'Id',
                    'sort' => 'Template.id',
                    'data_path' => 'Template.id',
                    'class' => 'short'
                ],
                [
                    'name' => 'Org',
                    'sort' => 'Organisation.name',
                    'data_path' => 'Organisation',
                    'element' => 'org',
                    'class' => 'short'
                ],
                [
                    'name' => 'Share',
                    'sort' => 'Template.share',
                    'data_path' => 'Template.share',
                    'element' => 'boolean',
                    'class' => 'short'
                ],
                [
                    'name' => 'Name',
                    'sort' => 'Template.org',
                    'data_path' => 'Template.org',
                    'class' => 'short'
                ],
                [
                    'name' => 'Description',
                    'sort' => 'Template.description',
                    'data_path' => 'Template.description',
                    'class' => 'bitwider'
                ]
            ],
            'actions' => [
                [
                    'url' => $baseurl . '/templates/view',
                    'url_params_data_paths' => ['Template.id'],
                    'icon' => 'eye'
                ],
                [
                    'url' => $baseurl . '/templates/edit',
                    'url_params_data_paths' => [
                        'Template.id'
                    ],
                    'icon' => 'edit',
                    'title' => 'Edit',
                ],
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/templates/delete/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'Template.id',
                    'icon' => 'trash',
                ]
            ]
        ]
    ]
]);
