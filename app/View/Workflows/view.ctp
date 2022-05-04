<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Workflow view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Name'),
                'path' => 'Workflow.name'
            ],
            [
                'key' => __('ID'),
                'path' => 'Workflow.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'Workflow.uuid'
            ],
            [
                'key' => __('Timestamp'),
                'path' => 'Workflow.url',
            ],
            [
                'key' => __('Owner Organisation'),
                'path' => 'Workflow.org_id',
                'pathName' => 'Organisation.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Description'),
                'path' => 'Workflow.description'
            ],
            [
                'key' => __('Data'),
                'path' => 'Workflow.data',
                'type' => 'json',
            ],
        ],
    ]
);
