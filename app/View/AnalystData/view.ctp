<?php
$fields = [
    [
        'key' => __('ID'),
        'path' => $modelSelection . '.id'
    ],
    [
        'key' => 'UUID',
        'path' => $modelSelection . '.uuid',
        'class' => '',
        'type' => 'uuid',
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
        'path' => $modelSelection . '.Orgc',
        'pathName' => $modelSelection . '.orgc_uuid',
        'type' => 'org',
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
        'sg_path' => $modelSelection . '.SharingGroup',
        'type' => 'distribution'
    ],
    [
        'key' => __('Authors'),
        'path' => $modelSelection . '.authors'
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
    $fields[] = [
        'key' => __('Opinion'),
        'path' => $modelSelection . '.opinion',
        'type' => 'opinion_scale',
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

$notes = $data[$modelSelection]['Note'] ?? [];
$opinions = $data[$modelSelection]['Opinion'] ?? [];
$relationships_outbound = $data[$modelSelection]['Relationship'] ?? [];
$relationships_inbound = $data[$modelSelection]['RelationshipInbound'] ?? [];
$notesOpinions = array_merge($notes, $opinions);
if(!function_exists("countNotes")) {
    function countNotes($notesOpinions) {
        $notesTotalCount = count($notesOpinions);
        $notesCount = 0;
        $relationsCount = 0;
        foreach ($notesOpinions as $notesOpinion) {
            if ($notesOpinion['note_type'] == 2) { // relationship
                $relationsCount += 1;
            } else {
                $notesCount += 1;
            }
            if (!empty($notesOpinion['Note'])) {
                $nestedCounts = countNotes($notesOpinion['Note']);
                $notesTotalCount += $nestedCounts['total'];
                $notesCount += $nestedCounts['notesOpinions'];
                $relationsCount += $nestedCounts['relations'];
            }
            if (!empty($notesOpinion['Opinion'])) {
                $nestedCounts = countNotes($notesOpinion['Opinion']);
                $notesTotalCount += $nestedCounts['total'];
                $notesCount += $nestedCounts['notesOpinions'];
                $relationsCount += $nestedCounts['relations'];
            }
        }
        return ['total' => $notesTotalCount, 'notesOpinions' => $notesCount, 'relations' => $relationsCount];
    }
}
$counts = countNotes($notesOpinions);
$notesOpinionCount = $counts['notesOpinions'];
$allCounts = [
    'notesOpinions' => $counts['notesOpinions'],
    'relationships_outbound' => count($relationships_outbound),
    'relationships_inbound' => count($relationships_inbound),
];

$options = [
    'container_id' => 'analyst_data_thread',
    'object_type' => $modelSelection,
    'object_uuid' => $object_uuid,
    'shortDist' => $shortDist,
    'notes' => $notes,
    'opinions' => $opinions,
    'relationships_outbound' => $relationships_outbound,
    'relationships_inbound' => $relationships_inbound,
    'allCounts' => $allCounts,
];

echo $this->element('genericElements/assetLoader', [
    'js' => ['doT', 'moment.min'],
    'css' => ['analyst-data',],
]);
echo $this->element('genericElements/Analyst_data/thread', $options);
?>

<?php if ($modelSelection == 'Relationship') : ?>
    <script>
        $(document).ready(function() {
            $('#analyst_data_thread').find('li > a[href^="#relationship"]').tab('show')
        })
    </script>
<?php endif; ?>