<?php
App::uses('IndexFilterState', 'Tools');
App::uses('IndexPicker', 'Tools');
App::uses('EventCardTool', 'Tools/EventOverview');
App::uses('DistributionLevel', 'Tools');

$this->set('headerTitle', __('Objects'));
$this->set('headerDescription', __('Objects from every event you can see, most recently changed first.'));
$this->set('headerActions', []);

$filterState = new IndexFilterState(
    $baseurl . '/objects/index',
    $this->request->params['named'] ?? [],
    '',
    $this->request->query ?? []
);
$filterLabels = $filterLabels ?? ['org' => [], 'sharinggroup' => []];

$canGraph = $this->Acl->canAccess('workspaces', 'addNodes');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Object.id',
        'card_section' => 'selector',
        'graph_item' => function ($row) {
            return ['type' => 'Object', 'uuid' => $row['Object']['uuid'], 'label' => $row['Object']['name']];
        },
    ],
    [
        'name' => __('Object'),
        'sort' => 'name',
        'class' => 'oi-col-object',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_object_cell', ['object' => $row['Object']]);
        },
    ],
    [
        'name' => __('References'),
        'class' => 'oi-col-refs',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_refs', [
                'out' => $row['Object']['references_out'] ?? 0,
                'in' => $row['Object']['references_in'] ?? 0,
            ]);
        },
    ],
    [
        'name' => __('Event'),
        'class' => 'oi-col-event',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) use ($baseurl) {
            return sprintf(
                '<a class="oi-event" href="%s/events/view/%d" title="%s"><span class="oi-event-id">#%d</span>'
                    . '<span class="oi-event-info">%s</span></a>',
                h($baseurl),
                (int)$row['Event']['id'],
                h($row['Event']['info']),
                (int)$row['Event']['id'],
                h($row['Event']['info'])
            );
        },
    ],
    [
        'name' => __('Creator org'),
        'class' => 'oi-col-org',
        'display_in' => ['table'],
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'requirement' => (bool)Configure::read('MISP.showorg'),
    ],
    [
        'name' => __('Seen'),
        'sort' => 'first_seen',
        'class' => 'oi-col-seen',
        'display_in' => ['table'],
        'element' => 'custom',
        'function' => function ($row) {
            return $this->element('Objects/index_seen', ['object' => $row['Object']]);
        },
    ],
    [
        'name' => __('Modified'),
        'sort' => 'timestamp',
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
    [
        'element' => 'row_actions',
        'data_path' => 'Object.id',
        'class' => 'oi-col-actions',
        'card_section' => 'actions',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('Open in event'),
                'icon' => 'arrow-up-right-from-square',
                'url' => $baseurl . '/events/view/%event%/object:%id%#tab-objects',
                'url_params_data_paths' => ['event' => 'Event.id'],
            ],
            [
                'type' => 'copy',
                'label' => __('Copy UUID'),
                'icon' => 'copy',
                'data_path' => 'Object.uuid',
                'copy_message' => __('UUID copied to clipboard'),
            ],
        ],
    ],
];

$children = [
    [
        'type' => 'search',
        'mode' => 'legacy',
        'name' => 'value',
        'button' => __('Search'),
        'placeholder' => __('Exact value or object UUID'),
        'chip_label' => __('Value'),
    ],
    [
        'type' => 'picker',
        'name' => 'template',
        'label' => __('Template'),
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'options' => $templateOptions,
        'exclude' => true,
        'separator' => '|',
        'hint' => __('Objects whose template is not installed can still be filtered from the URL.'),
    ],
];
// Always drawn, so applying a single template can swap it in live.
$children[] = [
    'type' => 'picker',
    'name' => 'relation',
    'label' => __('Relation'),
    'icon' => 'fas fa-diagram-project',
    'options' => array_map(function ($relation) {
        return ['value' => $relation, 'label' => $relation];
    }, $relationOptions),
    'single' => true,
    'hint' => __('Where the exact value must sit in the object.'),
    'disabled' => empty($relationOptions) ? __('Pick one installed template to choose a relation.') : null,
];
if ($canPickOrgs) {
    $children[] = [
        'type' => 'picker',
        'name' => 'org',
        'label' => __('Creator org'),
        'icon' => 'misp-icon misp-icon-organisation misp-simple',
        'source' => $baseurl . '/organisations/pickerSearch',
        'separator' => '|',
        'exclude' => true,
        'resolved' => $filterLabels['org'],
        'suggest' => IndexPicker::orgSuggestions($me, Hash::extract($objects, '{n}.Orgc')),
    ];
}
$distributionOptions = [];
foreach (DistributionLevel::all() as $level => $meta) {
    if ($level < 0 || $level > 5) {
        continue;
    }
    $badge = EventCardTool::distribution($level);
    $distributionOptions[] = [
        'value' => (string)$level,
        'label' => $level === 4 ? __('Any sharing group') : $meta['label'],
        'style' => ['badge' => $badge['icon'], 'css' => $badge['style']],
    ];
}
$children[] = [
    'type' => 'picker',
    'name' => 'distribution',
    'label' => __('Distribution'),
    'icon' => 'fas fa-share-nodes',
    'options' => $distributionOptions,
    'separator' => '|',
    'exclude' => true,
    'hint' => __('The object\'s own setting; "Inherited" follows its event.'),
    'sub' => [
        'option' => '4',
        'name' => 'sharinggroup',
        'label' => __('Sharing group'),
        'source' => $baseurl . '/sharing_groups/pickerSearch',
        'exclude' => true,
        'resolved' => $filterLabels['sharinggroup'],
        'hint' => __('Including a group keeps only objects shared with it.'),
    ],
];
$children[] = [
    'type' => 'time',
    'name' => 'time',
    'label' => __('Time'),
    'icon' => 'far fa-clock',
    'fields' => [
        ['name' => 'timestamp', 'label' => __('Modified')],
        ['name' => 'first_seen', 'label' => __('First seen')],
        ['name' => 'last_seen', 'label' => __('Last seen')],
    ],
    'presets' => [
        ['value' => '1d', 'label' => __('24h'), 'title' => __('last 24 hours')],
        ['value' => '7d', 'label' => __('7d'), 'title' => __('last 7 days')],
        ['value' => '30d', 'label' => __('30d'), 'title' => __('last 30 days')],
        ['value' => '90d', 'label' => __('90d'), 'title' => __('last 90 days')],
        ['value' => '365d', 'label' => __('1y'), 'title' => __('last year')],
    ],
];
$mine = $filterState->get('my_org') === '1';
$children[] = [
    'type' => 'button',
    'id' => 'oi-my-org',
    'label' => __('My org'),
    'icon' => 'misp-icon misp-icon-organisation misp-simple',
    'class' => 'btn btn-outline-primary',
    'pressed' => $mine,
    'url' => $filterState->url(['my_org' => $mine ? null : '1']),
];

$queryFilters = array_diff_key(
    $this->request->query ?? [],
    array_flip(['page', 'limit', 'sort', 'direction'])
);
$this->Paginator->options(['url' => ['?' => $queryFilters]]);

if (!empty($valueTruncated)) {
    echo sprintf(
        '<div class="container-fluid"><div class="alert alert-info oi-truncated py-2 mb-3">'
            . '<i class="fas fa-circle-info me-2"></i>%s</div></div>',
        h(__('This value sits in more than %s attributes; only the objects holding the first %s are listed.', number_format($valueRowCap), number_format($valueRowCap)))
    );
}

echo $this->element('genericElements/assetLoader', [
    'css' => ['objects-index'],
    'js' => ['objects-index'],
]);

echo '<div class="oi-index" data-oi-card-url="' . h($baseurl . '/objects/indexCard/') . '">';
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $objects,
            'primary_id_path' => 'Object.id',
            'table_class' => 'oi-table',
            'card_element' => 'Objects/index_card_tile',
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxl' => 3],
            'empty_message' => empty($filterState->filters())
                ? __('No objects in any event you can see.')
                : __('No object matches these filters.'),
            'fields' => $fields,
            'filter_bar' => [
                'pull' => 'right',
                'children' => $children,
                'transport' => 'query',
                'soft_delete' => '/deleteSelection',
                'mass_graph' => $canGraph,
                'chips' => [
                    'labels' => [
                        'template_uuid' => __('Template uuid'),
                        'event' => __('Event'),
                        'my_org' => __('Creator org'),
                        'relation' => __('Relation'),
                        'timestamp' => __('Modified'),
                        'first_seen' => __('First seen'),
                        'last_seen' => __('Last seen'),
                    ],
                    'values' => [
                        'my_org' => ['1' => __('mine')],
                    ],
                ],
            ],
        ],
    ],
    'item_url' => '/objects',
]);
echo '</div>';
