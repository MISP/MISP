<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Taxii Server view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Id'),
                'path' => 'TaxiiServer.id'
            ],
            [
                'key' => __('Name'),
                'path' => 'TaxiiServer.name'
            ],
            [
                'key' => __('Owner'),
                'path' => 'TaxiiServer.owner'
            ],
            [
                'key' => __('Base URL'),
                'path' => 'TaxiiServer.baseurl'
            ],
            [
                'key' => __('API Root'),
                'path' => 'TaxiiServer.api_root'
            ],
            [
                'key' => __('Selected Collection'),
                'path' => 'TaxiiServer.collection'
            ],
            [
                'key' => __('Description'),
                'path' => 'TaxiiServer.description'
            ],
            [
                'key' => __('Filters'),
                'path' => 'TaxiiServer.filters',
                'type' => 'json'
            ],
            [
                'key' => __('Owner Organisation'),
                'path' => 'TaxiiServer.Cerebrate.org_id',
                'pathName' => 'Organisation.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('API key'),
                'path' => 'TaxiiServer.api_key'
            ],
            [
                'key' => __('Description'),
                'path' => 'TaxiiServer.Cerebrate.description'
            ],
        ],
        'children' => [
            [
                'url' => '/taxii_servers/collectionsIndex/{{0}}/',
                'url_params' => ['TaxiiServer.id'],
                'title' => __('Collections'),
                'elementId' => 'taxii_collections'
            ],
            [
                'url' => '/taxii_servers/objectsIndex/{{0}}/{{1}}/',
                'url_params' => ['TaxiiServer.id', 'TaxiiServer.collection'],
                'title' => __('Objects in selected Collection'),
                'elementId' => 'taxii_objects'
            ],
        ]
    ]
);
