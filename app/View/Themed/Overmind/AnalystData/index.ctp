<?php

$m = $modelSelection;
$viewUrl = $baseurl . '/analystData/view/' . $m . '/%id%';
$canEdit = function ($row) use ($m) {
    return !empty($row[$m]['_canEdit']);
};

// ---- Fields --------------------------------------------------------------
$fields = [];


$fields[] = [
    'element' => 'checkbox',
    'data_path' => $m . '.id',
    'card_section' => 'selector',
];

$fields[] = [
    'name' => __('ID'),
    'sort' => $m . '.id',
    'data_path' => $m . '.id',
    'element' => 'id',
    'url' => $viewUrl,
    'card_section' => 'top',
    'display_in' => ['table', 'card'],
];

$fields[] = [
    'name' => __('UUID'),
    'data_path' => $m . '.uuid',
    'element' => 'uuid',
    'url' => $viewUrl,
    'card_section' => 'top',
    'display_in' => ['card'],
];


$fields[] = [
    'name' => __('Distribution'),
    'sort' => $m . '.distribution',
    'data_path' => $m . '.distribution',
    'element' => 'distribution',
    'card_section' => 'top',
    'display_in' => ['table', 'card'],
];


$fields[] = [
    'name' => __('Target'),
    'element' => 'analyst_object_ref',
    'type_path' => $m . '.object_type',
    'uuid_path' => $m . '.object_uuid',
    'card_section' => 'title',
    'display_in' => ['table', 'card'],
];

// 4+. Type-specific columns
if ($m === 'Note') {
    $fields[] = [
        'name' => __('Note'),
        'sort' => $m . '.note',
        'data_path' => $m . '.note',
        'class' => 'idx-col-wrap',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ];
    $fields[] = [
        'name' => __('Language'),
        'sort' => $m . '.language',
        'data_path' => $m . '.language',
        'element' => 'analyst_language',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ];
} else if ($m === 'Opinion') {
    $fields[] = [
        'name' => __('Opinion'),
        'sort' => $m . '.opinion',
        'element' => 'analyst_opinion',
        'model' => $m,
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ];
} else if ($m === 'Relationship') {
    $fields[] = [
        'name' => __('Relationship type'),
        'sort' => $m . '.relationship_type',
        'data_path' => $m . '.relationship_type',
        'card_section' => 'links',
        'display_in' => ['table', 'card'],
    ];
    $fields[] = [
        'name' => __('Related object'),
        'element' => 'analyst_object_ref',
        'type_path' => $m . '.related_object_type',
        'uuid_path' => $m . '.related_object_uuid',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ];
}


$fields[] = [
    'name' => __('Created'),
    'sort' => $m . '.created',
    'data_path' => $m . '.created',
    'element' => 'datetime',
    'card_section' => 'meta',
    'display_in' => ['card'],
];
$fields[] = [
    'name' => __('Modified'),
    'sort' => $m . '.modified',
    'data_path' => $m . '.modified',
    'element' => 'datetime',
    'card_section' => 'meta',
    'display_in' => ['card'],
];


$fields[] = [
    'name' => __('Creator org'),
    'sort' => $m . '.orgc_uuid',
    'data_path' => $m . '.Orgc',
    'element' => 'organisation',
    'card_section' => 'meta',
    'display_in' => ['table', 'card'],
];


$fields[] = [
    'name' => __('Actions'),
    'element' => 'row_actions',
    'data_path' => $m . '.id',
    'card_section' => 'extra',
    'actions' => [
        [
            'type' => 'navigate',
            'label' => __('View'),
            'icon' => 'eye',
            'url' => $viewUrl,
        ],
        [
            'type' => 'modal',
            'label' => __('Edit'),
            'icon' => 'pen-to-square',
            'url' => $baseurl . '/analystData/edit/' . $m . '/%id%',
            'requirement' => $canEdit,
        ],
        [
            'type' => 'modal',
            'label' => __('Delete'),
            'icon' => 'trash',
            'class' => 'text-danger',
            'url' => $baseurl . '/analystData/delete/' . $m . '/%id%',
            'requirement' => $canEdit,
        ],
    ],
];

?>

<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => $m . '.id',
            'row_dblclick_url' => $viewUrl,
            'filter_bar' => [
                'children' => [
                    [
                        'type' => 'search',
                        'mode' => 'quickFilter',
                        'placeholder' => __('Search %s…', strtolower($m)),
                    ],
                ],
                // The type is baked into the URL so deleteSelection knows which model to hit.
                'delete' => '/deleteSelection/' . $m,
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/analystData',
]);
?>
