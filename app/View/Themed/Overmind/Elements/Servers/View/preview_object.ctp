<?php
/**
 * The Objects tab of a remote event preview (feed, server), drawn as the
 * event's own Objects tab (Elements/Objects/index.ctp) with the same parts,
 * read-only: a table whose rows open into their attributes, or cards.
 * The remote event is on hand whole, so the tab filters it here.
 */

// The objects index's rows read attributes' tags as AttributeTag; MISP JSON
// carries them as Tag. A feed's objects have no id: their position stands in.
$objects = [];
foreach ($data['objects'] ?? [] as $previewObject) {
    if (($previewObject['objectType'] ?? '') !== 'object') {
        continue;
    }
    foreach ($previewObject['Attribute'] ?? [] as $i => $attribute) {
        if (!isset($attribute['AttributeTag'])) {
            $previewObject['Attribute'][$i]['AttributeTag'] = array_map(function ($tag) {
                return ['Tag' => $tag];
            }, $attribute['Tag'] ?? []);
        }
    }
    $previewObject['id'] = $previewObject['id'] ?? count($objects) + 1;
    $objects[] = $previewObject;
}

App::uses('RemoteEventPreviewFilter', 'Tools');
$filters = RemoteEventPreviewFilter::active(
    $this->request->params['named'] ?? [],
    RemoteEventPreviewFilter::OBJECT_FILTERS
);
$panelChildren = RemoteEventPreviewFilter::children(
    array_merge(...array_column($objects, 'Attribute')),
    $objects,
    RemoteEventPreviewFilter::OBJECT_FILTERS
);
$referencesIn = [];
foreach ($objects as $object) {
    foreach ($object['ObjectReference'] ?? [] as $reference) {
        $uuid = $reference['referenced_uuid'] ?? '';
        $referencesIn[$uuid] = ($referencesIn[$uuid] ?? 0) + 1;
    }
}
$objects = RemoteEventPreviewFilter::objects($objects, $filters);
$tabUrl = $previewContext['objectsUrl'] ?? '';
$uid = 'preview-objects-' . h($data['Event']['id'] ?? $data['Event']['uuid'] ?? '0');

$rows = [];
foreach ($objects as $object) {
    $attrs = $object['Attribute'] ?? [];
    $first = empty($attrs) ? null : reset($attrs);
    $headline = $first === null ? null : [
        'relation' => (string)($first['object_relation'] ?? ''),
        'value' => (string)($first['value'] ?? ''),
    ];
    $rows[] = [
        'Object' => $object + [
            'attribute_count' => count($attrs),
            'headline' => $headline,
            'references_out' => count($object['ObjectReference'] ?? []),
            'references_in' => $referencesIn[$object['uuid'] ?? ''] ?? 0,
        ],
        // As $objContext in Elements/Objects/index.ctp has it, with nothing to edit.
        'ctx' => [
            'attrs' => $attrs,
            'deleted' => !empty($object['deleted']),
            'origin' => null,
            'foreign' => false,
            'canEdit' => false,
            'canTag' => false,
            'graphItem' => null,
            'headline' => $headline,
            'expand' => false,
        ],
        'open' => false,
    ];
}

// The event's Objects tab's columns, less the selection, the actions and the
// relationship menu, whose targets are this instance's.
$fields = [
    [
        'name' => __('Object'),
        'class' => 'oi-col-object',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_object_cell', [
                'object' => $row['Object'],
                'open' => $row['open'],
            ]);
        },
    ],
    [
        'name' => __('References'),
        'class' => 'oi-col-refs',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_refs', [
                'out' => $row['Object']['references_out'],
                'in' => $row['Object']['references_in'],
            ]);
        },
    ],
    [
        'name' => __('Seen'),
        'class' => 'oi-col-seen',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_seen', ['object' => $row['Object']]);
        },
    ],
    [
        'name' => __('Modified'),
        'class' => 'oi-col-modified',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_modified', ['object' => $row['Object']]);
        },
    ],
    [
        'name' => __('Analyst data'),
        'header_html' => sprintf(
            '<span title="%s"><i class="misp-icon misp-icon-analyst-note misp-simple"></i></span>',
            h(__('Analyst data'))
        ),
        'class' => 'oi-col-analyst',
        'card_section' => 'analyst',
        'element' => 'analyst_data_badges',
        'note_path' => 'Object.Note',
        'opinion_path' => 'Object.Opinion',
        'relationship_path' => 'Object.Relationship',
        'relationship_inbound_path' => 'Object.RelationshipInbound',
        'uuid_path' => 'Object.uuid',
        'object_type' => 'Object',
    ],
    // A card opens on the attribute list, as the event's Objects tab's cards do.
    [
        'display_in' => ['card'],
        'card_section' => 'attributes',
        'element' => 'custom',
        'function' => function ($row) {
            return '<div class="oi-card">' . $this->element('Objects/object_attribute_list', [
                'attrs' => $row['ctx']['attrs'],
                'showActions' => false,
                'readonly' => true,
                'remote' => true,
            ]) . '</div>';
        },
    ],
];
$columnCount = count(array_filter($fields, function ($field) {
    return empty($field['display_in']) || in_array('table', $field['display_in'], true);
}));

$indexData = ['data' => [
    'data' => $rows,
    'fields' => $fields,
    'table_class' => 'oi-table',
    'card_element' => 'Objects/index_card_tile',
    'cards_per_row' => ['' => 1, 'lg' => 2, 'xxl' => 3],
    'empty_message' => empty($filters)
        ? __('No objects in this event.')
        : __('No object matches these filters.'),
    'row_class_callable' => function ($row) {
        return $row['ctx']['deleted'] ? 'oi-deleted' : '';
    },
    // The attribute table under each object, open or not.
    'row_after_callable' => function ($row) use ($columnCount) {
        return $this->element('Objects/object_index_detail', [
            'object' => $row['Object'],
            'ctx' => $row['ctx'],
            'columns' => $columnCount,
            'readonly' => true,
        ]);
    },
]];

// The fold controls only have something to act on once the tab holds an object.
$foldChildren = empty($objects) ? [] : [
    [
        'type' => 'button_group',
        'label' => __('Expand or collapse every object'),
        'buttons' => [
            [
                'class' => 'obj-expand-all',
                'icon' => 'fas fa-angles-down',
                'label' => __('Expand all'),
            ],
            [
                'class' => 'obj-collapse-all',
                'icon' => 'fas fa-angles-up',
                'label' => __('Collapse all'),
            ],
        ],
    ],
];
?>

<div id="<?= $uid ?>-container">
<div id="objectListContainer" class="container-fluid px-0" data-ifp-scope="<?= h($tabUrl) ?>">

    <!-- ── Filter bar, as the scaffold draws it ──── -->
    <div class="ifp-card">
        <?= $this->element('genericElementsBS5/IndexTable/filter_bar', [
            'scaffold_data' => [
                // For the count beside the chips.
                'data' => $objects,
                'filter_bar' => [
                    'base_url' => $tabUrl,
                    'skip_pagination' => true,
                    'chips' => ['labels' => ['name' => __('Template')]],
                    'children' => array_merge([
                        [
                            'type' => 'search',
                            'button' => __('Search'),
                            'placeholder' => __('Filter objects…'),
                            'mode' => 'legacy',
                            'name' => 'searchFor',
                        ],
                    ], $panelChildren, $foldChildren),
                ],
            ],
            'item_url' => '/objects',
        ]) ?>
    </div>

    <!-- ── Objects, laid out as the event's Objects tab ──────── -->
    <div class="oi-index">
        <div class="card shadow-sm mb-4">
            <div class="card-body p-0">
                <div id="objTableView">
                    <?= $this->element('genericElementsBS5/IndexTable/index_table', [
                        'scaffold_data' => $indexData,
                    ]) ?>
                </div>
                <div id="objCardView" class="d-none">
                    <?= $this->element('genericElementsBS5/IndexTable/index_card', [
                        'scaffold_data' => $indexData,
                    ]) ?>
                </div>
            </div>
        </div>
    </div>

</div>
</div>

<script>
(function () {
    var list = document.getElementById(<?= json_encode($uid . '-container') ?>);
    if (list && window.ObjectsIndex) {
        window.ObjectsIndex.bindList(list.closest('.ajax-tab-content') || list);
    }
}());
</script>
