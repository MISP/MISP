<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => $data['module_type'] == 'trigger' ? __('Trigger module view') : __('Workflow module view'),
        'data' => $data,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('Name'),
                'path' => 'name',
                'class' => 'bold',
                'type' => 'custom',
                'function' => function ($row) {
                    return sprintf('<i class="fa-fw %s"></i> %s', $this->FontAwesome->getClass($row['icon']), h($row['name']));
                }
            ],
            [
                'key' => __('Module Type'),
                'path' => 'module_type'
            ],
            [
                'key' => __('Is MISP module'),
                'type' => 'boolean',
                'path' => 'is_misp_module'
            ],
            [
                'key' => __('Description'),
                'path' => 'description'
            ],
            [
                'key' => __('Module Enabled'),
                'type' => 'boolean',
                'path' => 'disabled',
                'element' => 'boolean',
                'mapping' => [
                    true => '<i class="fas fa-times"></i>',
                    false => '<i class="fas fa-check"></i>'
                ],
            ],
            [
                'key' => __('Module Parameters'),
                'type' => 'json',
                'path' => 'params',
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
                'key' => __('Workflow Data'),
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
    .restrict-height>div {
        height: 200px;
        overflow: auto;
        resize: both;
    }
</style>