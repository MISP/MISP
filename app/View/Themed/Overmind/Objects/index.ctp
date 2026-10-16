<?php
App::uses('IndexFilterState', 'Tools');
App::uses('IndexPicker', 'Tools');
App::uses('EventCardTool', 'Tools/EventOverview');
App::uses('DistributionLevel', 'Tools');
App::uses('CakeTime', 'Utility');

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

$fields = [
    [
        'name' => __('Object'),
        'sort' => 'name',
        'class' => 'oi-col-object',
        'element' => 'custom',
        'function' => function ($row) {
            $object = $row['Object'];
            $headline = $object['headline'] ?? null;
            $html = sprintf(
                '<div class="oi-object"><button type="button" class="oi-expand" data-oi-expand="%s"'
                    . ' aria-expanded="false" title="%s"><i class="fas fa-chevron-right"></i></button>%s</div>',
                (int)$object['id'],
                h(__('Show its attributes')),
                $this->element('Objects/object_header', [
                    'object' => $object,
                    'ctx' => [
                        'count' => (int)($object['attribute_count'] ?? 0),
                        'deleted' => false,
                        'firstValue' => $headline === null ? '' : (string)$headline['value'],
                        'firstRelation' => $headline === null ? '' : $headline['relation'],
                    ],
                ])
            );
            if (!empty($object['comment'])) {
                $html .= sprintf(
                    '<div class="oi-comment" title="%s"><i class="fas fa-comment"></i> %s</div>',
                    h($object['comment']),
                    h($object['comment'])
                );
            }
            return $html;
        },
    ],
    [
        'name' => __('References'),
        'class' => 'oi-col-refs',
        'element' => 'custom',
        'function' => function ($row) {
            $out = (int)($row['Object']['references_out'] ?? 0);
            $in = (int)($row['Object']['references_in'] ?? 0);
            return sprintf(
                '<span class="oi-refs%s" title="%s"><span><i class="fas fa-arrow-right"></i> %d</span>'
                    . '<span><i class="fas fa-arrow-left"></i> %d</span></span>',
                $out + $in === 0 ? ' is-empty' : '',
                h(__('%s outgoing, %s incoming references', $out, $in)),
                $out,
                $in
            );
        },
    ],
    [
        'name' => __('Event'),
        'class' => 'oi-col-event',
        'element' => 'custom',
        'function' => function ($row) use ($baseurl) {
            return sprintf(
                '<a class="oi-event" href="%s/events/view2/%d" title="%s"><span class="oi-event-id">#%d</span>'
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
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'requirement' => (bool)Configure::read('MISP.showorg'),
    ],
    [
        'name' => __('Seen'),
        'sort' => 'first_seen',
        'class' => 'oi-col-seen',
        'element' => 'custom',
        'function' => function ($row) {
            $day = function ($value) {
                $dt = date_create((string)$value);
                return $dt === false ? (string)$value : $dt->format('Y-m-d');
            };
            $first = $row['Object']['first_seen'] ?? null;
            $last = $row['Object']['last_seen'] ?? null;
            if (empty($first) && empty($last)) {
                return '<span class="oi-none">&mdash;</span>';
            }
            return sprintf(
                '<span class="oi-seen" title="%s">%s<span class="oi-seen-dash">&ndash;</span>%s</span>',
                h(__('First seen %s, last seen %s', $first ?: '?', $last ?: '?')),
                empty($first) ? '?' : h($day($first)),
                empty($last) ? '?' : h($day($last))
            );
        },
    ],
    [
        'name' => __('Modified'),
        'sort' => 'timestamp',
        'class' => 'oi-col-modified',
        'element' => 'custom',
        'function' => function ($row) {
            $ts = (int)$row['Object']['timestamp'];
            $label = $ts < strtotime('-1 year')
                ? date('Y-m-d', $ts)
                : CakeTime::timeAgoInWords($ts, [
                    'accuracy' => ['day' => 'day', 'week' => 'day', 'month' => 'week'],
                ]);
            return sprintf(
                '<span class="oi-modified" title="%s">%s</span>',
                h(date('Y-m-d H:i:s', $ts)),
                h($label)
            );
        },
    ],
    [
        'name' => __('Analyst data'),
        'header_html' => sprintf(
            '<span title="%s"><i class="misp-icon misp-icon-analyst-note misp-simple"></i></span>',
            h(__('Analyst data'))
        ),
        'class' => 'oi-col-analyst',
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
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('Open in event'),
                'icon' => 'arrow-up-right-from-square',
                'url' => $baseurl . '/events/view2/%event%/object:%id%#tab-objects',
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
            'fields' => $fields,
            'filter_bar' => [
                'pull' => 'right',
                'children' => $children,
                'apply' => 'draft',
                'transport' => 'query',
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
