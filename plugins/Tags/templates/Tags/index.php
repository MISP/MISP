<?php
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        'data' => [
                            'type' => 'simple',
                            'text' => __('Add tag'),
                            'popover_url' => '/tags/add',
                            'button' => [
                                'icon' => 'plus',
                            ]
                        ]
                    ]
                ],
                [
                    'type' => 'context_filters',
                    'context_filters' => $filteringContexts
                ],
                [
                    'type' => 'search',
                    'button' => __('Search'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'value'
                ]
            ]
        ],
        'fields' => [
            [
                'name' => '#',
                'sort' => 'id',
                'data_path' => 'id',
            ],
            [
                'name' => __('Name'),
                'sort' => 'name',
                'element' => 'tag'
            ],
            [
                'name' => __('Counter'),
                'sort' => 'couter',
                'data_path' => 'counter',
            ],
            [
                'name' => __('Colour'),
                'sort' => 'colour',
                'data_path' => 'colour',
            ],
            [
                'name' => __('Created'),
                'sort' => 'created',
                'data_path' => 'created',
            ],
        ],
        'title' => __('Tag index'),
        'description' => __('The list of all tags existing on this instance'),
        'actions' => [
            [
                'url' => '/tags/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye'
            ],
            [
                'open_modal' => '/tags/edit/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'edit'
            ],
            [
                'open_modal' => '/tags/delete/[onclick_params_data_path]',
                'modal_params_data_path' => 'id',
                'icon' => 'trash'
            ],
        ]
    ]
]);
echo '</div>';
?>
