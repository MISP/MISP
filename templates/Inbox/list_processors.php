<?php
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'skip_pagination' => true,
        'data' => $data,
        'top_bar' => [
            'children' => [
                [
                    'type' => 'context_filters',
                    'context_filters' => !empty($filteringContexts) ? $filteringContexts : []
                ],
                [
                    'type' => 'search',
                    'button' => __('Search'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'value',
                    'allowFilering' => true
                ]
            ]
        ],
        'fields' => [
            [
                'name' => __('Enabled'),
                'data_path' => 'enabled',
                'element' => 'boolean'
            ],
            [
                'name' => __('Processor scope'),
                'data_path' => 'scope',
            ],
            [
                'name' => __('Processor action'),
                'data_path' => 'action',
            ],
            [
                'name' => __('Description'),
                'data_path' => 'description',
            ],
            [
                'name' => __('Notice'),
                'data_path' => 'notice',
            ],
            [
                'name' => __('Error'),
                'data_path' => 'error',
            ],
        ],
        'title' => __('Available Inbox Request Processors'),
        'description' => __('The list of Inbox Request Processors available on this server.'),
        'actions' => [
        ]
    ]
]);