<?php
$fields = [
    [
        'key' => __('ID'),
        'path' => $modelSelection . '.id'
    ],
    [
        'key' => __('UUID'),
        'path' => $modelSelection . '.uuid'
    ],
    [
        'key' => __('Note Type'),
        'path' => $modelSelection . '.note_type_name'
    ],
    [
        'key' => __('Target Object'),
        'type' => 'custom',
        'function' => function (array $row) use ($baseurl, $modelSelection) {
            $path = Inflector::pluralize(strtolower($row[$modelSelection]['object_type']));
            return sprintf(
                '<span class="bold">%s</span>: <a href="%s/%s/view/%s">%s</a>',
                h($row[$modelSelection]['object_type']),
                h($baseurl),
                h($path),
                h($row[$modelSelection]['object_uuid']),
                h($row[$modelSelection]['object_uuid'])
            );
        }
    ],
    [
        'key' => __('Creator org'),
        'path' => $modelSelection . '.orgc_uuid',
        'pathName' => $modelSelection . '.orgc_uuid',
        'type' => 'model',
        'model' => 'organisations'
    ],
    [
        'key' => __('Owner org'),
        'path' => $modelSelection . '.org_uuid',
        'pathName' => $modelSelection . '.org_uuid',
        'type' => 'model',
        'model' => 'organisations'
    ],
    [
        'key' => __('Created'),
        'path' => $modelSelection . '.created'
    ],
    [
        'key' => __('Modified'),
        'path' => $modelSelection . '.modified'
    ],
    [
        'key' => __('Distribution'),
        'path' => $modelSelection . '.distribution',
        'event_id_path' => $modelSelection . '.id',
        'disable_distribution_graph' => true,
        'sg_path' => $modelSelection . '.sharing_group_id',
        'type' => 'distribution'
    ],
];

if ($modelSelection === 'Note') {
    $fields[] = [
        'key' => __('Language'),
        'path' => $modelSelection . '.language'
    ];
    $fields[] = [
        'key' => __('Note'),
        'path' => $modelSelection . '.note'
    ];
} else if ($modelSelection === 'Opinion') {
    $fields[] = [
        'key' => __('Comment'),
        'path' => $modelSelection . '.comment'
    ];

} else if ($modelSelection === 'Relationship') {
    $fields[] = [
        'key' => __('Related Object'),
        'type' => 'custom',
        'function' => function (array $row) use ($baseurl, $modelSelection) {
            $path = Inflector::pluralize(strtolower($row[$modelSelection]['related_object_type']));
            return sprintf(
                '<span class="bold">%s</span>: <a href="%s/%s/view/%s">%s</a>',
                h($row[$modelSelection]['related_object_type']),
                h($baseurl),
                h($path),
                h($row[$modelSelection]['related_object_uuid']),
                h($row[$modelSelection]['related_object_uuid'])
            );
        }
    ];
    $fields[] = [
        'key' => __('Relationship_type'),
        'path' => $modelSelection . '.relationship_type'
    ];
}

echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('%s view', h($modelSelection)),
        'data' => $data,
        'fields' => $fields,
        'side_panels' => [
            [
                'type' => 'html',
                'html' => '<div id="analyst_data_thread" class="panel-container"></div>',
            ]
        ],
    ]
);

$object_uuid = Hash::get($data, $modelSelection . '.uuid');
$options = [
    'container_id' => 'analyst_data_thread',
    'object_type' => $modelSelection,
    'object_uuid' => $object_uuid,
    'shortDist' => $shortDist,
];

if ($modelSelection == 'Note') {
    $options['notes'] = [$data[$modelSelection]];
} else if ($modelSelection == 'Opinion') {
    $options['opinions'] = [$data[$modelSelection]];
} else if ($modelSelection == 'Relationship') {
    $options['relationships'] = [$data[$modelSelection]];
}

echo $this->element('genericElements/Analyst_data/thread', $options);
?>

<?php if ($modelSelection == 'Relationship'): ?>
    <script>
        $(document).ready(function() {
            $('#analyst_data_thread').find('li > a[href^="#relationship"]').tab('show')
        })
    </script>
<?php endif; ?>