<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Collection view'),
        'data' => $data,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'Collection.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'Collection.uuid'
            ],
            [
                'key' => __('Creator org'),
                'path' => 'Collection.orgc_id',
                'pathName' =>  'Collection.Orgc.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Owner org'),
                'path' => 'Collection.org_id',
                'pathName' => 'Collection.Org.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Created'),
                'path' => 'Collection.created'
            ],
            [
                'key' => __('Modified'),
                'path' => 'Collection.modified'
            ],
            [
                'key' => __('Name'),
                'path' => 'Collection.name'
            ],
            [
                'key' => __('Description'),
                'path' => 'Collection.description'
            ],
            [
                'key' => __('Distribution'),
                'path' => 'Collection.distribution',
                'event_id_path' => 'Collection.id',
                'disable_distribution_graph' => true,
                'sg_path' => 'Collection.sharing_group_id',
                'type' => 'distribution'
            ]
        ],
        'children' => [
            [
                'url' => '/collectionElements/index/{{0}}/',
                'url_params' => ['Collection.id'],
                'title' => __('Collection elements'),
                'elementId' => 'preview_elements_container'
            ]
        ]
    ]
);
