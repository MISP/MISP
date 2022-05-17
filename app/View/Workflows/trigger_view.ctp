<?php
// debug($data);
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Trigger view',
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
                'key' => __('Description'),
                'path' => 'description'
            ],
            [
                'key' => __('Trigger Enabled'),
                'type' => 'boolean',
                'path' => 'enabled',
            ],
            [
                'key' => __('Execution Order'),
                'type' => 'custom',
                'function' => function ($row) {
                    return $this->element('Workflows/executionOrder', ['trigger' => $row]);
                }
            ],
        ],
    ]
);

?>
