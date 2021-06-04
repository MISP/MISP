<?php
$fullTitle = [
    'local' => [
        'main' => __('Local organisations'),
        'extra' => __(', both local and remote'),
    ],
    'external' => [
        'main' => __('Known remote organisations'),
        'extra' => __(' on other instances'),
    ],
    'all' => [
        'main' => __('All organisations'),
        'extra' => __(' having a presence on this instance'),
    ]
    ];

echo '<div class="index">';
echo $this->element('/genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $orgs,
        'top_bar' => [
            'children' => [
                [
                    'children' => [
                        [
                            'text' => $fullTitle['local']['main'],
                            'active' => $scope === 'local',
                            'url' => $baseurl . '/organisations/index/scope:local'
                        ],
                        [
                            'text' => $fullTitle['external']['main'],
                            'active' => $scope === 'external',
                            'url' => $baseurl . '/organisations/index/scope:external'
                        ],
                        [
                            'text' => $fullTitle['all']['main'],
                            'active' => $scope === 'all',
                            'url' => $baseurl . '/organisations/index/scope:all'
                        ],
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
        'title' => $fullTitle[$scope]['main'] . $fullTitle[$scope]['extra'],
        'primary_id_path' => 'Organisation.id',
        'fields' => [
            [
                'name' => __('ID'),
                'sort' => 'id',
                'class' => 'short',
                'data_path' => 'Organisation.id',
                'element' => 'links',
                'url' => $baseurl . '/organisations/view/%s'
            ],
            [
                'name' => __('Name'),
                'sort' => 'name',
                'data_path' => 'Organisation.name',
            ],
            [
                'name' => __('UUID'),
                'sort' => 'uuid',
                'data_path' => 'Organisation.uuid',
                'class' => 'quickSelect',
                'requirements' => $isSiteAdmin
            ],
            [
                'name' => __('Description'),
                'data_path' => 'Organisation.description',
            ],
            [
                'name' => __('Nationality'),
                'data_path' => 'Organisation',
                'class' => 'short',
                'element' => 'country',
            ],
            [
                'name' => __('Sector'),
                'data_path' => 'Organisation.sector',
            ],
            [
                'name' => __('Type'),
                'data_path' => 'Organisation.type',
            ],
            [
                'name' => __('Contacts'),
                'data_path' => 'Organisation.contacts',
            ],
            [
                'name' => __('Added by'),
                'sort' => 'created_by_email',
                'data_path' => 'Organisation.created_by_email',
                'requirements' => $isSiteAdmin
            ],
            [
                'name' => __('Local'),
                'sort' => 'local',
                'element' => 'boolean',
                'data_path' => 'Organisation.local',
                'colors' => true,
            ],
            [
                'name' => __('Users'),
                'sort' => 'user_count',
                'data_path' => 'Organisation.user_count',
            ],
            [
                'name' => __('Restrictions'),
                'sort' => 'restricted_to_domain',
                'data_path' => 'Organisation.restricted_to_domain',
                'array_implode_glue' => '<br/>',
            ],
        ],
        'actions' => [
            [
                'url' => '/organisations/view',
                'url_params_data_paths' => [
                    'Organisation.id'
                ],
                'icon' => 'eye',
                'title' => __('View'),
                'dbclickAction' => true,
            ],
            [
                'url' => '/admin/organisations/edit',
                'url_params_data_paths' => [
                    'Organisation.id'
                ],
                'icon' => 'edit',
                'title' => __('Edit'),
                'requirements' => $isSiteAdmin
            ],
            [
                'title' => __('Delete'),
                'icon' => 'trash',
                'url' => '/admin/organisations/delete',
                'url_params_data_paths' => array('Organisation.id'),
                'postLink' => true,
                'postLinkConfirm' => __('Are you sure you want to delete the Organisation?'),
                'requirements' => $isSiteAdmin
            ],
        ]
    ]
]);
echo '</div>';
if ($isSiteAdmin) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'indexOrg'));
} else {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'indexOrg'));
}