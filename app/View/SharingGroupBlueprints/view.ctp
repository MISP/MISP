<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Sharing Group Blueprint view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Id'),
                'path' => 'SharingGroupBlueprint.id'
            ],
            [
                'key' => __('Uuid'),
                'path' => 'SharingGroupBlueprint.uuid'
            ],
            [
                'key' => __('Owner Organisation'),
                'path' => 'SharingGroupBlueprint.org_id',
                'pathName' => 'Organisation.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Name'),
                'path' => 'SharingGroupBlueprint.name'
            ],
            [
                'key' => __('Description'),
                'path' => 'SharingGroupBlueprint.description'
            ],
            [
                'key' => __('SharingGroup'),
                'path' => 'SharingGroupBlueprint.sharing_group_id',
                'pathName' => 'SharingGroup.name',
                'type' => 'model',
                'model' => 'sharing_groups',
                'error' => __('No Sharing group assigned yet, execute the Sharing Group Blueprint first.')
            ],
            [
                'key' => __('Rules'),
                'path' => 'SharingGroupBlueprint.rules',
                'type' => 'json'
            ],
        ],
        'children' => [
            [
                'url' => '/SharingGroupBlueprints/viewOrgs/{{0}}/',
                'url_params' => ['SharingGroupBlueprint.id'],
                'title' => __('Organisations'),
                'elementId' => 'preview_orgs_container'
            ]
        ]
    ]
);
