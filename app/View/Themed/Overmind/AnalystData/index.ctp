<?php

$m = $modelSelection;
$workspaceGraphUuid = $workspaceGraphUuid ?? null;
$viewUrl = $baseurl . '/analystData/view/' . $m . '/%id%';
$canEdit = function ($row) use ($m) {
    return !empty($row[$m]['_canEdit']);
};

// ---- Fields --------------------------------------------------------------
$col = [];

$col['checkbox'] = [
    'element' => 'checkbox',
    'data_path' => $m . '.id',
    'card_section' => 'selector',
];
$col['id'] = [
    'name' => __('ID'),
    'sort' => $m . '.id',
    'data_path' => $m . '.id',
    'element' => 'id',
    'url' => $viewUrl,
    'display_in' => ['table'],
];
$col['distribution'] = [
    'name' => __('Distribution'),
    'sort' => $m . '.distribution',
    'data_path' => $m . '.distribution',
    'element' => 'distribution',
    'display_in' => ['table'],
];
$col['target'] = [
    'name' => __('Target'),
    'element' => 'analyst_object_ref',
    'type_path' => $m . '.object_type',
    'uuid_path' => $m . '.object_uuid',
    'sha256_path' => $m . '.object_sha256',
    'display_in' => ['table'],
];
$col['orgc'] = [
    'name' => __('Creator org'),
    'sort' => $m . '.orgc_uuid',
    'data_path' => $m . '.Orgc',
    'element' => 'organisation',
    'org_title' => __('Created by %s'),
    'fit' => true,
    'display_in' => ['table'],
];

if ($m === 'Note') {
    $col['note'] = [
        'name' => __('Note'),
        'sort' => $m . '.note',
        'data_path' => $m . '.note',
        'element' => 'analyst_text',
        'display_in' => ['table'],
    ];
    $col['language'] = [
        'name' => __('Language'),
        'sort' => $m . '.language',
        'data_path' => $m . '.language',
        'element' => 'analyst_language',
        'display_in' => ['table'],
    ];
    $order = ['checkbox', 'id', 'note', 'target', 'language', 'orgc', 'distribution'];
} else if ($m === 'Opinion') {
    $col['opinion'] = [
        'name' => __('Opinion'),
        'sort' => $m . '.opinion',
        'data_path' => $m . '.comment',
        'opinion_path' => $m . '.opinion',
        'element' => 'analyst_text',
        'display_in' => ['table'],
    ];
    $order = ['checkbox', 'id', 'opinion', 'target', 'orgc', 'distribution'];
} else if ($m === 'Graph') {
    echo $this->element('genericElements/assetLoader', [
        'js' => ['intel-graph-thumb', 'intel-graph-thumbs'],
        'css' => ['intel-graph-thumbs'],
    ]);
    $col['name'] = [
        'name' => __('Name'),
        'sort' => $m . '.name',
        'element' => 'custom',
        // The graph's picture (intel-graph-thumbs.js) beside its name
        'function' => function ($row) use ($workspaceGraphUuid) {
            $mark = '';
            if (!empty($workspaceGraphUuid) && strtolower($row['Graph']['uuid']) === $workspaceGraphUuid) {
                $mark = sprintf(
                    ' <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-semibold ms-1" title="%s">'
                    . '<i class="fas fa-bullseye me-1" aria-hidden="true"></i>%s</span>',
                    h(__('It lays out your workspace')),
                    h(__('Workspace'))
                );
            }
            return sprintf(
                '<div class="igt-cell" data-tour="graph-row"><span data-intel-graph-thumb="%s" data-revision="%s" data-surface="index" data-name="%s"></span><span>%s%s</span></div>',
                h($row['Graph']['uuid']),
                h($row['Graph']['revision'] ?? ''),
                h($row['Graph']['name']),
                h($row['Graph']['name']),
                $mark
            );
        },
        'class' => 'idx-col-wrap',
        'display_in' => ['table'],
    ];
    $col['nodes'] = [
        'name' => __('Nodes'),
        'data_path' => $m . '.node_count',
        'element' => 'count',
        'display_in' => ['table'],
    ];
    $col['forked'] = [
        'name' => __('Forked from'),
        'element' => 'custom',
        'function' => function ($row) use ($baseurl) {
            if (empty($row['Graph']['forked_from_uuid'])) {
                return '';
            }
            $icon = '<i class="fas fa-code-fork me-1 text-body-secondary" aria-hidden="true"></i>';
            $parent = $row['Graph']['forked_from'] ?? null;
            if ($parent === null) {
                return $icon . '<span class="text-body-secondary">' . __('A fork') . '</span>';
            }
            return $icon . sprintf(
                '<a href="%s">%s</a>',
                h($baseurl . '/analyst_graphs/view/' . $parent['uuid']),
                h($parent['name'])
            );
        },
        'display_in' => ['table'],
    ];
    $order = ['checkbox', 'id', 'name', 'target', 'nodes', 'orgc', 'distribution', 'forked'];
} else {
    $col['relationship_type'] = [
        'name' => __('Relationship type'),
        'sort' => $m . '.relationship_type',
        'data_path' => $m . '.relationship_type',
        'display_in' => ['table'],
    ];
    $col['related'] = [
        'name' => __('Related object'),
        'element' => 'analyst_object_ref',
        'type_path' => $m . '.related_object_type',
        'uuid_path' => $m . '.related_object_uuid',
        'sha256_path' => $m . '.related_object_sha256',
        'display_in' => ['table'],
    ];
    $order = ['checkbox', 'id', 'target', 'relationship_type', 'related', 'orgc', 'distribution'];
}

// The table's columns in $order. The cards (AnalystData/index_card) draw
// the record themselves and take only the selection box and the menu.
$fields = [];
foreach ($order as $key) {
    $fields[] = $col[$key];
}

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
            'type' => 'navigate',
            'label' => __('Export'),
            'icon' => 'file-export',
            'url' => $baseurl . '/analyst_graphs/export/%uuid%',
            'url_params_data_paths' => ['uuid' => $m . '.uuid'],
            'requirement' => $m === 'Graph',
        ],
        [
            'type' => 'modal',
            'label' => __('Edit'),
            'icon' => 'pen-to-square',
            'url' => $baseurl . '/analystData/edit/' . $m . '/%id%',
            'requirement' => $m === 'Graph' ? false : $canEdit,
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
echo $this->element('genericElements/assetLoader', [
    'css' => ['events-index-cards', 'analyst-data-index'],
    'js' => ['events-index-cards'],
]);
echo $this->OrgGrade->config($orgGrading ?? null);
// The events index's cards and grid (events-index-cards.css) hang off .dk-index
echo '<div class="dk-index adk-index">';
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => $m . '.id',
            'cards_per_row' => 1,
            'card_element' => 'AnalystData/index_card',
            'row_dblclick_url' => $viewUrl,
            'filter_bar' => [
                'children' => [
                    [
                        'type' => 'search',
                        'mode' => 'quickFilter',
                        'placeholder' => $m === 'Graph' ? __('Search saved graphs…') : __('Search %s…', strtolower($m)),
                    ],
                ],
                // The type is baked into the URL so deleteSelection knows which model to hit.
                'delete' => '/deleteSelection/' . $m,
                'custom_actions' => $m !== 'Graph' ? [] : [
                    [
                        'id' => 'multi-export-graphs-button',
                        'label' => __('Export'),
                        'icon' => 'file-export',
                        'onclick' => sprintf(
                            "if (selectedItems.size) { window.location = '%s/analyst_graphs/export/' + JSON.stringify(Array.from(selectedItems.keys())); }",
                            $baseurl
                        ),
                    ],
                ],
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/analystData',
]);
echo '</div>';
?>
