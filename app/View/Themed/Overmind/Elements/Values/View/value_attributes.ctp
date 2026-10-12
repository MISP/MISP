<?php
$fields = [
    [
        'name' => __('Event'),
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $baseurl . '/events/view2/%id%',
    ],
    [
        'name' => __('Event info'),
        'data_path' => 'Event',
        'element' => 'event_info',
    ],
    [
        'name' => __('Creator Org'),
        'data_path' => 'Event.Orgc',
        'element' => 'organisation',
    ],
    [
        'name' => __('Category'),
        'data_path' => 'Attribute.category',
        'element' => 'category',
    ],
    [
        'name' => __('Type'),
        'data_path' => 'Attribute.type',
        'element' => 'type',
    ],
    [
        'name' => __('Attribute value'),
        'element' => 'custom',
        'function' => function (array $row) {
            return '<span class="font-monospace text-break">' . h($row['Attribute']['value']) . '</span>';
        },
    ],
    [
        'name' => __('Object'),
        'element' => 'custom',
        'function' => function (array $row) {
            return empty($row['Attribute']['object_id']) ? '' : h($row['Object']['name'] ?? '');
        },
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'AttributeTag',
        'element' => 'tag_list',
    ],
    [
        'name' => __('IDS'),
        'element' => 'custom',
        'function' => function (array $row) {
            return empty($row['Attribute']['to_ids'])
                ? '<i class="fas fa-shield-alt text-secondary" title="' . h(__('IDS inactive')) . '"></i>'
                : '<i class="fas fa-shield-alt text-warning" title="' . h(__('IDS active')) . '"></i>';
        },
    ],
    [
        'name' => __('Last modified'),
        'data_path' => 'Attribute.timestamp',
        'element' => 'datetime',
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data['Attribute'],
            'paginatorOptions' => ['url' => [$data['Value']['id']]],
            'primary_id_path' => 'Event.id',
            'row_dblclick_url' => $baseurl . '/events/view2/%id%',
            'fields' => $fields,
        ],
    ],
    'item_url' => '/values',
]);
