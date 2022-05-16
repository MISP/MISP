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
                'path' => 'Workflow.timestamp',
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
                'key' => __('Run counter'),
                'path' => 'Workflow.counter',
                'type' => 'custom',
                'function' => function ($row) {
                    return h($row['Workflow']['counter']);
                }
            ],
            [
                'key' => __('Priority Level'),
                'path' => 'Workflow.priority_level',
                'type' => 'custom',
                'function' => function ($row) {
                    return h($row['Workflow']['priority_level']);
                }
            ],
            [
                'key' => __('Listening Triggers'),
                'path' => 'Workflow.listening_triggers',
                'type' => 'custom',
                'function' => function ($row) {
                    return implode('<br />', array_map(function($trigger) {
                        return sprintf('<a href="/workflows/trigger_view/%s">%s</a>', h($trigger), h($trigger));
                    }, $row['Workflow']['listening_triggers']));
                }
            ],
            [
                'key' => __('Data'),
                'class' => 'restrict-height',
                'path' => 'Workflow.data',
                'type' => 'json',
            ],
        ],
        'append' => [
            ['element' => 'Workflows/executionPath', 'element_params' => ['workflow' => $data['Workflow']]],
        ]
    ]
);

?>

<style>
    .sidebar-workflow-block {
        display: inline-block;
        background-color: #fff;
        border-radius: 5px;
        margin: 0.25em 0.5em;
        padding: 0.25em;
        box-shadow: 0px 3px 6px 2px #33333311;
    }

    .restrict-height>.json_container_Data {
        height: 200px;
        overflow: auto;
        resize: both;
    }
</style>