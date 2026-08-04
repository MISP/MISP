<?php
$append = [];
if ($data['module_type'] == 'trigger') {
    $append = [
        ['element' => 'Workflows/executionPath', 'element_params' => ['workflow' => $data['Workflow']]],
    ];
}
$append[] = ['element' => 'Workflows/execute_module', 'element_params' => ['module' => $data]];
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
                'function' => function ($row) use ($baseurl) {
                    if (!empty($row['icon'])) {
                        return sprintf('<i class="fa-fw %s"></i> %s', $this->FontAwesome->getClass($row['icon']), h($row['name']));
                    } else if (!empty($row['icon_path'])) {
                        return sprintf('<img src="%s" alt="Icon of %s" style="width: 12px; filter: grayscale(1);"> %s', sprintf('%s/%s/%s', $baseurl, 'img', h($row['icon_path'])), h($row['name']), h($row['name']));
                    }
                    return h($row['name']);
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
                'class' => 'restrict-height',
                'type' => 'json',
                'path' => 'params',
            ],
            [
                'key' => __('Run counter'),
                'path' => 'Workflow.counter',
                'type' => 'custom',
                'requirement' => $data['module_type'] == 'trigger',
                'function' => function ($row) {
                    return h($row['Workflow']['counter']);
                }
            ],
            [
                'key' => __('Listening Workflows'),
                'type' => 'json',
                'path' => 'listening_workflows',
                'requirement' => $data['module_type'] == 'trigger',
            ],
            [
                'key' => __('Workflow Data'),
                'class' => 'restrict-height',
                'path' => 'Workflow.data',
                'type' => 'json',
                'requirement' => $data['module_type'] == 'trigger',
            ],
        ],
        'append' => $append,
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
