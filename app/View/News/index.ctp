<?php

$this->set('menuData', ['menuList' => 'news', 'menuItem' => 'index']);

echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $newsItems,
            'fields' => [
                [
                    'name' => __('Id'),
                    'sort' => 'id',
                    'data_path' => 'News.id'
                ],
                [
                    'name' => __('User'),
                    'sort' => 'email',
                    'data_path' => 'User.email'
                ],
                [
                    'name' => __('Title'),
                    'sort' => 'title',
                    'data_path' => 'News.title'
                ],
                [
                    'name' => __('Message'),
                    'sort' => 'message',
                    'data_path' => 'News.message'
                ],
                [
                    'name' => __('Created at'),
                    'sort' => 'date_created',
                    'data_path' => 'News.date_created',
                    'element' => 'datetime'
                ],

            ],
            'title' => empty($ajax) ? __('News') : false,
            'pull' => 'right',
            'actions' => [
                [
                    'url' => $baseurl . '/news/edit',
                    'url_params_data_paths' => [
                        'News.id'
                    ],
                    'icon' => 'edit',
                    'title' => 'Edit News',
                ],
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/news/delete/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'News.id',
                    'icon' => 'trash',
                    'title' => __('Delete news'),
                ]
            ]
        ]
    ]
]);
