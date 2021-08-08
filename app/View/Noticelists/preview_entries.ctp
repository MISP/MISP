<?php
$fields = [
    [
        'name' => __('Scope'),
        'data_path' => 'data.scope',
        'class' => 'short'
    ],
    [
        'name' => __('Field'),
        'data_path' => 'data.field',
        'class' => 'short'
    ],
    [
        'name' => __('Value'),
        'data_path' => 'data.value',
        'class' => 'shortish'
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'data.tags',
        'class' => 'shortish'
    ],
    [
        'name' => __('Message'),
        'data_path' => 'data.message.en',
        'class' => 'shortish'
    ],
];

echo $this->element('genericElements/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'fields' => $fields,
            'title' => 'Values',
            'paginatorOptions' => [
                'url' => [$noticelist['Noticelist']['id']]
            ],
            'persistUrlParams' => [0, 'quickFilter']
        ],
        'containerId' => 'preview_entries_container'
    ]
]);
?>
<script type="text/javascript">
    var passedArgsArray = <?= json_encode([h($noticelist['Noticelist']['id'])]) ?>;
</script>