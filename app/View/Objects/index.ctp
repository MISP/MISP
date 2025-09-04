<?php
echo '<div class="index">';
echo $this->element('/genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'children' => [
                [
                    'children' => [
                        [
                            'text' => __('Add'),
                            'fa-icon' => 'plus',
                            'url' => $baseurl . '/admin/objects/add',
                            'requirement' => $isSiteAdmin,
                        ]
                    ]
                ],
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'cancel' => array(
                        'fa-icon' => 'times',
                        'title' => __('Remove filters'),
                        'onClick' => 'cancelSearch',
                    )
                ]
            ],
        ],
        'title' => __('Objects'),
        'primary_id_path' => 'Object.id',
        'fields' => [
            [
                'name' => __('ID'),
                'sort' => 'id',
                'class' => 'short',
                'data_path' => 'Object.id',
                'element' => 'links',
                'url' => $baseurl . '/objects/view/%s'
            ],
            [
                'name' => __('Name'),
                'sort' => 'name',
                'data_path' => 'Object',
                'element' => 'org'
            ],
            [
                'name' => __('UUID'),
                'sort' => 'uuid',
                'data_path' => 'Object.uuid',
                'class' => 'quickSelect'
            ],
            [
                'name' => __('Value'),
                'sort' => 'value',
                'data_path' => 'Attribute.0.value',
                'class' => 'quickSelect'

            ],
            [
                'name' => __('Comment'),
                'sort' => 'comment',
                'data_path' => 'Object.comment'
            ],
        ],
        'actions' => [
            [
                'url' => '/objects/view',
                'url_params_data_paths' => [
                    'Object.id'
                ],
                'icon' => 'eye',
                'title' => __('View'),
            ],
            [
                'url' => '/admin/objects/edit',
                'url_params_data_paths' => [
                    'Object.id'
                ],
                'icon' => 'edit',
                'title' => __('Edit'),
                'requirement' => $isSiteAdmin
            ],
            [
                'title' => __('Delete'),
                'icon' => 'trash',
                'url' => '/admin/objects/delete',
                'url_params_data_paths' => array('Object.id'),
                'postLink' => true,
                'postLinkConfirm' => __('Are you sure you want to delete the Object?'),
                'requirement' => $isSiteAdmin
            ],
        ],
        'child_rows' => [
            'path' => 'Attribute',
            'fields' => [
                [
                    'name' => __('ID'),
                    'class' => 'short',
                    'data_path' => 'id',
                    'element' => 'links',
                    'url' => $baseurl . '/attributes/view/%s'
                ],
                [
                    'name' => __('Type'),
                    'class' => 'short',
                    'data_path' => 'type',
                ],
            ]
        ]
    ]
]);
echo '</div>';