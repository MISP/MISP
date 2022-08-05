<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Workflow blueprint view',
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
                'key' => __('Preview'),
                'path' => 'WorkflowBlueprint.mermaid',
                'type' => 'custom',
                'function' => function(array $data) {
                    $mermaid = [
                        'markdown' => sprintf('```mermaid%s%s```', PHP_EOL, $data['WorkflowBlueprint']['mermaid'], PHP_EOL)
                    ];
                    $data['WorkflowBlueprint']['markdown'] = sprintf('```mermaid%s%s```', PHP_EOL, $data['WorkflowBlueprint']['mermaid'], PHP_EOL);
                    return $this->element('genericElements/SingleViews/Fields/markdownField', [
                        'data' => $data,
                        'field' => [
                            'path' => 'WorkflowBlueprint.markdown',
                            'path_id' => 'WorkflowBlueprint.id'
                        ]
                    ]);
                }
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
