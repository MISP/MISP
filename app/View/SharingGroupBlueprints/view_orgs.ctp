<?php
    echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'skip_pagination' => 1,
            'data' => $data,
            'fields' => [
                [
                    'name' => __('Id'),
                    'sort' => 'Organisation.id',
                    'data_path' => 'Organisation.id'
                ],
                [
                    'name' => __('Uuid'),
                    'sort' => 'Organisation.uuid',
                    'data_path' => 'Organisation.uuid'
                ],
                [
                    'name' => __('name'),
                    'sort' => 'Organisation.name',
                    'data_path' => 'Organisation.name'
                ],
                [
                    'name' => __('sector'),
                    'sort' => 'Organisation.sector',
                    'data_path' => 'Organisation.sector'
                ],
                [
                    'name' => __('type'),
                    'sort' => 'Organisation.type',
                    'data_path' => 'Organisation.type'
                ],
                [
                    'name' => __('nationality'),
                    'sort' => 'Organisation.nationality',
                    'data_path' => 'Organisation.nationality'
                ]
            ],
            'title' => false,
            'description' => __('Organisations that would end up in a sharing group with the current SharingGroupBlueprint blueprint.'),
            'actions' => [
                [
                    'url' => $baseurl . '/organisations/view',
                    'url_params_data_paths' => ['Organisation.id'],
                    'icon' => 'eye'
                ]
            ]
        ]
    ]);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
?>
