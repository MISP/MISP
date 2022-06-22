<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Workflow view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Name'),
                'path' => 'WorkflowPart.name'
            ],
            [
                'key' => __('ID'),
                'path' => 'WorkflowPart.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'WorkflowPart.uuid'
            ],
            [
                'key' => __('Timestamp'),
                'path' => 'WorkflowPart.timestamp',
            ],
            [
                'key' => __('Description'),
                'path' => 'WorkflowPart.description'
            ],
            [
                'key' => __('Data'),
                'class' => 'restrict-height',
                'path' => 'WorkflowPart.data',
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