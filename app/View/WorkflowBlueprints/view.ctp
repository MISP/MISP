<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Workflow view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Name'),
                'path' => 'WorkflowBlueprint.name'
            ],
            [
                'key' => __('ID'),
                'path' => 'WorkflowBlueprint.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'WorkflowBlueprint.uuid'
            ],
            [
                'key' => __('Timestamp'),
                'path' => 'WorkflowBlueprint.timestamp',
            ],
            [
                'key' => __('Description'),
                'path' => 'WorkflowBlueprint.description'
            ],
            [
                'key' => __('Data'),
                'class' => 'restrict-height',
                'path' => 'WorkflowBlueprint.data',
                'type' => 'json',
            ],
        ],
    ]
);

?>

<style>
    .restrict-height > div {
        height: 200px;
        overflow: auto;
        resize: both;
    }
</style>