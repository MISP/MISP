<?php
$fields = [
    [
        'name' => __('Created'),
        'sort' => 'created',
        'data_path' => 'created'
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'data_path' => 'User.email'
    ],
    [
        'name' => __('IP'),
        'data_path' => 'ip'
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Organisation.name',
        'element' => 'org',
        'data_path' => 'Organisation',
        'class' => 'short',
    ],
    [
        'name' => __('Request Method'),
        'sort' => 'request_method',
        'data_path' => 'request_method'
    ],
    [
        'name' => __('URL'),
        'sort' => 'url',
        'data_path' => 'url'
    ],
    [
        'name' => __('Response Code'),
        'sort' => 'response_code',
        'data_path' => 'response_code'
    ],
    [
        'name' => __('Memory Usage'),
        'sort' => 'memory_usage',
        'data_path' => 'memory_usage'
    ],
    [
        'name' => __('Duration'),
        'sort' => 'duration',
        'data_path' => 'duration'
    ],
    [
        'name' => __('Queries'),
        'sort' => 'query_count',
        'data_path' => 'query_count'
    ],
];


echo $this->element(
    'genericElements/IndexTable/index_table',
    [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'context_filters',
                    ],
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value',
                        'allowFilering' => true
                    ],
                ]
            ],
            'fields' => $fields,
            'title' => empty($ajax) ? __('Access Logs') : false
        ]
    ]
);
// TODO: [3.x-MIGRATION] add ajax dialog for request body, sql queries and human readable memory usage and duration