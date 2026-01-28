<?php
    echo '<div class="regexp index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'title' => __('Import Regexp'),
            'data' => $list,
            'fields' => [
                [
                    'name' => __('ID'),
                    'sort' => 'Regexp.id',
                    'class' => 'short',
                    'data_path' => 'Regexp.id',
                ],
                [
                    'name' => __('Exportable'),
                    'sort' => 'Regexp.regexp',
                    'class' => 'custom-element',
                    'data_path' => 'Regexp.regexp',
                ],
                [
                    'name' => __('Replacement'),
                    'sort' => 'Regexp.replacement',
                    'class' => 'custom-element',
                    'data_path' => 'Regexp.replacement',
                ],
                [
                    'name' => __('Type'),
                    'sort' => 'Regexp.type',
                    'class' => 'short',
                    'data_path' => 'Regexp.type',
                ]
            ],
            'actions' => [
            [
                'url' => "$baseurl/admin/regexp/edit",
                'url_params_data_paths' => [
                    'Regexp.id'
                ],
                'icon' => 'edit',
                'title' => __('Edit'),
                'requirement' => $isSiteAdmin,
            ],
            [
                'url' => "$baseurl/admin/regexp/delete",
                'url_params_data_paths' => [
                    'Regexp.id'
                ],
                'postLink' => '',
                'postLinkConfirm' => __('Are you sure you want to delete this Regexp?'),
                'icon' => 'trash',
                'title' => __('Delete Regexp'),
                'requirement' => $isSiteAdmin,
            ],
            ]
        ]
    ]);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'regexp', 'menuItem' => 'index'));
?>
