<?php
$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id'
    ],
    [
        'name' => __('Date Created'),
        'sort' => 'date_created',
        'data_path' => 'date_created'
    ],
    [
        'name' => __('Date Modified'),
        'sort' => 'date_modified',
        'data_path' => 'date_modified'
    ],
    [
        'name' => __('Process ID'),
        'data_path' => 'process_id'
    ],
    [
        'name' => __('Worker'),
        'sort' => 'worker',
        'data_path' => 'worker'
    ],
    [
        'name' => __('Job Type'),
        'sort' => 'job_type',
        'data_path' => 'job_type'
    ],
    [
        'name' => __('Job Input'),
        'data_path' => 'job_input'
    ],
    [
        'name' => __('Message'),
        'data_path' => 'message'
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Organisation.name',
        'element' => 'org',
        'data_path' => 'Organisation',
        'class' => 'short',
    ],
    [
        'name' => __('Status'),
        'sort' => 'job_status',
        'data_path' => 'job_status'
    ],
    [
        'name' => __('Progress'),
        'data_path' => 'progress'
    ],
];


echo $this->element(
    'genericElements/IndexTable/index_table',
    [
        'data' => [
            'data' => $jobs,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'context_filters',
                    ]
                ]
            ],
            'fields' => $fields,
            'title' => empty($ajax) ? __('Jobs') : false
        ]
    ]
);
