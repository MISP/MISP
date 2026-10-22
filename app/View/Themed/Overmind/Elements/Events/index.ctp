<?php
/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 *
 * Possible fields for each entry:
 *
 * - name           : Label displayed in the table
 * - header_html    : Label as markup, in place of name
 * - sort           : Database field used for sorting
 * - data_path      : Path to the data in the $events array
 * - element        : Template used for rendering
 * - url            : Associated link (supports %id%)
 * - card_section   : Display section in card mode
 * - display_in     : ['table', 'card']
 * - mode           : Specific option for certain elements (ex: timestamp)
 * - actions        : Available actions (for element = selector)
 *
 * Fields specific to actions:
 *
 * - type           : link | ajax | toggle | divider
 * - label          : Displayed text
 * - label_on/off   : Text for toggle
 * - icon           : FontAwesome icon
 * - icon_on/off    : Toggle icon
 * - url            : URL (supports %id% and %action%)
 * - class          : CSS class
 * - requirement    : Permission check function
 * - state_path       : Path to the boolean a toggle flips
 *
 * The table's columns are the event_* field elements; the card draws
 * itself (Events/index_card) and shares only the checkbox and the actions.
 */

$possible = $possibleColumns ?? [];
$offered = function ($column) use ($possible) {
    return in_array($column, $possible, true);
};
// Columns the instance offers but the reader has hidden: rendered, and
// hidden by the style below, so the chooser can show them without a reload.
$hiddenColumns = array_values(array_diff($possible, $columns ?? []));

/*
 * The chooser, in the order it lists them: column key => setting name in
 * `event_index_hide_columns`, label, icon. Reports, sightings, proposals
 * and discussions are parts of the extras column.
 */
$chooser = [
    'owner' => ['owner_org', __('Owner org'), ''],
    'user' => ['creator_user', __('Creator user'), ''],
    'ext' => ['is_extension', __('Extension'), '<i class="fas fa-code-branch"></i>'],
    'ctx' => ['clusters', __('Tags & galaxies'), '<i class="misp-icon misp-icon-galaxy misp-simple"></i>'],
    'attrs' => ['attribute_count', __('Attributes & objects'), '<i class="misp-icon misp-icon-attribute misp-simple text-attribute"></i>'],
    'corr' => ['correlations', __('Correlations'), '<i class="fas fa-link text-correlation"></i>'],
    'reps' => ['report_count', __('Reports'), '<i class="misp-icon misp-icon-report misp-simple text-report"></i>'],
    'sight' => ['sightings', __('Sightings'), '<i class="misp-icon misp-icon-sighting misp-simple text-sighting"></i>'],
    'prop' => ['proposals', __('Proposals'), '<i class="fas fa-comment-medical"></i>'],
    'disc' => ['discussion', __('Discussions'), '<i class="fas fa-comments"></i>'],
    'changed' => ['timestamp', __('Last change'), '<i class="fas fa-pen"></i>'],
    'pub' => ['publish_timestamp', __('Published at'), '<i class="fas fa-upload"></i>'],
];
$chooserItems = '';
foreach ($chooser as [$setting, $label, $chooserIcon]) {
    if (!$offered($setting)) {
        continue;
    }
    $chooserItems .= sprintf(
        '<label data-te-opt="%s"><input class="form-check-input" type="checkbox" value="%s"%s><span class="te-cols-ic">%s</span>%s<small hidden></small></label>',
        h($setting),
        h($setting),
        in_array($setting, $hiddenColumns, true) ? '' : ' checked',
        $chooserIcon,
        h($label)
    );
}
$chooserHtml = sprintf(
    '<div class="dropdown te-chooser"><button type="button" class="te-gear" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false" title="%s" aria-label="%s"><i class="fas fa-table-columns"></i></button>'
        . '<div class="dropdown-menu dropdown-menu-end shadow te-cols" role="group" aria-label="%s"><h6>%s</h6>%s'
        . '<div class="te-cols-foot"><span class="te-cols-note"></span><span>'
        . '<button type="button" data-te-reset-widths hidden>%s</button>'
        . '<button type="button" data-te-reset>%s</button></span></div></div></div>',
    h(__('Choose columns')),
    h(__('Choose columns')),
    h(__('Columns')),
    h(__('Columns')),
    $chooserItems,
    h(__('Reset widths')),
    h(__('Reset'))
);

$col = function ($key, array $field, $class = '') {
    $class = trim('te-c-' . $key . ' ' . $class);
    return $field + [
        'class' => $class,
        'header_class' => $class,
        'display_in' => ['table'],
    ];
};
$icon = function ($html) {
    return '<span class="te-hicon">' . $html . '</span>';
};
$lane = function ($key, $lane, $title = null) use ($col, $offered) {
    return $col($key, [
        'element' => 'event_lane',
        'lane' => $lane,
        'requirement' => $offered('clusters'),
        'header_html' => '<span class="te-lanecap"' . ($title ? ' title="' . h($title) . '"' : '') . '>'
            . $this->EventIndex->laneIcon($lane) . '<span>' . h($this->EventIndex->laneLabel($lane)) . '</span></span>',
    ], 'te-lane');
};
$count = function ($key, $count, $setting, $iconHtml, $title) use ($col, $icon, $offered) {
    return $col($key, [
        'element' => 'event_count',
        'count' => $count,
        'header_html' => $icon($iconHtml),
        'header_title' => $title,
        'requirement' => $offered($setting),
    ], 'te-num');
};

$canGraph = $this->Acl->canAccess('analystGraphs', 'addNodes');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Event.id',
        'publish_path' => 'Event.published',
        'graph_item' => function ($row) {
            return ['type' => 'Event', 'uuid' => $row['Event']['uuid'], 'label' => $row['Event']['info']];
        },
        'card_section' => 'selector',
        'class' => 'te-c-sel',
        'header_class' => 'te-c-sel',
    ],
    $col('state', [
        'element' => 'event_state',
        'header_html' => $icon('<i class="fas fa-upload"></i>'),
        'header_title' => __('Publish state'),
    ]),
    $col('id', [
        'name' => __('ID'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $baseurl . '/events/view/%id%',
    ]),
    $col('title', [
        'name' => __('Title'),
        'sort' => 'Event.info',
        'element' => 'event_title',
    ]),
    $col('orgc', [
        'header_html' => '<span class="te-long">' . h(__('Creator org')) . '</span><span class="te-short">' . h(__('Creator')) . '</span>',
        'sort' => 'Orgc.name',
        'element' => 'event_orgc',
    ]),
    $col('owner', [
        'name' => __('Owner org'),
        'element' => 'event_owner',
        'requirement' => $offered('owner_org'),
    ]),
    $col('user', [
        'name' => __('Creator user'),
        'element' => 'event_creator_user',
        'requirement' => $offered('creator_user'),
    ]),
    $col('mk', [
        'name' => __('Markings'),
        'header_title' => __('Markings your analyst profile pins'),
        'element' => 'event_markings',
    ]),
    $lane('attrib', 'attribution'),
    $lane('behav', 'behaviour', __('ATT&CK techniques (count, then ids), then mitigations')),
    $lane('classif', 'classification', __('Other clusters, then tags')),
    $count('attrs', 'attributes', 'attribute_count', '<i class="misp-icon misp-icon-attribute misp-simple text-attribute"></i>', __('Attributes')),
    $count('objs', 'objects', 'attribute_count', '<i class="misp-icon misp-icon-object misp-simple text-object"></i>', __('Objects')),
    $count('corr', 'correlations', 'correlations', '<i class="fas fa-link text-correlation"></i>', __('Correlations')),
    $col('extras', [
        'element' => 'event_extras',
        'header_html' => '<span class="te-hicon te-hx"><i class="misp-icon misp-icon-analyst-graph misp-simple text-analystGraph"></i><i class="misp-icon misp-icon-report misp-simple text-report"></i><i class="misp-icon misp-icon-sighting misp-simple text-sighting"></i><i class="fas fa-comments"></i></span>',
        'header_title' => __('Analyst graphs, reports, sightings, proposals and discussions, when there are any'),
    ]),
    $col('ext', [
        'name' => __('Extension'),
        'element' => 'event_extension',
        'requirement' => $offered('is_extension'),
    ]),
    $col('dist', [
        'element' => 'event_distribution',
        'sort' => 'Event.distribution',
        'header_html' => $icon('<i class="fas fa-share-nodes"></i>'),
        'header_title' => __('Distribution'),
    ]),
    $col('date', [
        'name' => __('Date'),
        'header_title' => __('Event date'),
        'sort' => 'Event.date',
        'element' => 'event_date',
    ]),
    $col('pub', [
        'name' => __('Published'),
        'header_title' => __('Published at'),
        'sort' => 'Event.publish_timestamp',
        'element' => 'event_published',
        'requirement' => $offered('publish_timestamp'),
    ]),
    $col('changed', [
        'name' => __('Changed'),
        'header_title' => __('Last change'),
        'sort' => 'Event.timestamp',
        'element' => 'event_changed',
        'requirement' => $offered('timestamp'),
    ]),
    [
        'header_html' => $chooserHtml,
        'element' => 'row_actions',
        'data_path' => 'Event.id',
        'publish_path' => 'Event.published',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'class' => 'te-c-act',
        'header_class' => 'te-c-act',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/events/view/%id%'
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/events/edit/%id%',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/events/delete/%id%',
                'class' => 'text-danger',
                'requirement' => 'check_edit_rights'
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => 'check_publish_rights'
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Unpublish'),
                'label_off' => __('Publish'),
                'icon_on' => 'eye-slash',
                'icon_off' => 'upload',
                'url' => $baseurl . '/events/%action%/%id%',
                'state_path' => 'Event.published',
                'requirement' => 'check_publish_rights'
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $canGraph,
            ],
            [
                'type' => 'intelGraph',
                'label' => __('Add to graph'),
                'icon' => 'text-analystGraph misp-icon misp-icon-analyst-graph misp-simple',
                'items' => function ($row) {
                    return [['type' => 'Event', 'uuid' => $row['Event']['uuid'], 'label' => $row['Event']['info']]];
                },
                'requirement' => $canGraph,
            ]
        ]
    ],
];

// The hidden columns, hidden before the table script runs.
$hiddenRules = [];
foreach ($chooser as $key => [$setting]) {
    if (!in_array($setting, $hiddenColumns, true)) {
        continue;
    }
    if (in_array($key, ['reps', 'sight', 'prop', 'disc'], true)) {
        $hiddenRules[] = '.te-index .te-table .dk-x-' . $setting;
        continue;
    }
    $keys = ['ctx' => ['attrib', 'behav', 'classif'], 'attrs' => ['attrs', 'objs']][$key] ?? [$key];
    foreach ($keys as $k) {
        $hiddenRules[] = '.te-index .te-table .te-c-' . $k;
    }
}
$tableConfig = [
    'hidden' => $hiddenColumns,
    'saved' => $savedHiddenColumns ?? null,
    'defaults' => array_values(array_intersect(['is_extension', 'publish_timestamp', 'owner_org', 'creator_user'], $possible)),
    'graded' => $this->OrgGrade->enabled($orgGrading ?? null) || !empty(array_filter(array_map(function ($event) {
        return $event['EventCard']['grade'] ?? null;
    }, $events))),
];

$children = [];

$children[] = [
    'type' => 'search',
    'button' => 'Search',
    'placeholder' => 'Search by info, ID or UUID',
    'name'        => 'eventinfo',
    'mode'        => 'event',
    'id_field'    => 'eventid',
];

App::uses('IndexFilterState', 'Tools');
App::uses('IndexPicker', 'Tools');
App::uses('EventCardTool', 'Tools/EventOverview');
$filterState = new IndexFilterState($baseurl . '/events/index', $this->request->params['named'] ?? [], 'search');
$canPickOrgs = IndexPicker::canPickOrgs($me);
$filterLabels = $filterLabels ?? ['org' => [], 'tag' => [], 'galaxy' => []];

if ($canPickOrgs) {
    $children[] = [
        'type' => 'picker',
        'name' => 'org',
        'label' => __('Creator org'),
        'icon' => 'misp-icon misp-icon-organisation misp-simple',
        'source' => $baseurl . '/organisations/pickerSearch',
        'exclude' => true,
        'resolved' => $filterLabels['org'],
        'suggest' => IndexPicker::orgSuggestions($me, array_column($events ?? [], 'Orgc')),
    ];
}
$children[] = [
    'type' => 'picker',
    'name' => 'tag',
    'label' => __('Tag'),
    'icon' => 'fas fa-tag',
    'source' => $baseurl . '/tags/pickerSearch',
    'exclude' => true,
    'all_of' => true,
    'resolved' => $filterLabels['tag'],
    'hint' => __('Event or attribute tags.'),
    'browser' => [
        'kind' => 'tag',
        'scopes' => $baseurl . '/tags/pickerScopes',
        'tree' => $baseurl . '/tags/pickerTree',
    ],
];
if ($filterState->get('tags') !== null) {
    $children[] = [
        'type' => 'picker',
        'name' => 'tags',
        'label' => __('And tag'),
        'icon' => 'fas fa-tags',
        'source' => $baseurl . '/tags/pickerSearch',
        'exclude' => true,
        'resolved' => $filterLabels['tags'] ?? [],
        'hint' => __('Also carried by the event or one of its attributes.'),
    ];
}
$children[] = [
    'type' => 'picker',
    'name' => 'galaxy',
    'label' => __('Galaxy'),
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
    'source' => $baseurl . '/galaxy_clusters/pickerSearch',
    'exclude' => true,
    'resolved' => $filterLabels['galaxy'],
    'hint' => __('Clusters attached to the event.'),
    'browser' => [
        'kind' => 'galaxy',
        'scopes' => $baseurl . '/galaxies/pickerScopes',
    ],
];
$distributionOptions = [];
foreach ([0, 1, 2, 3, 4] as $level) {
    $badge = EventCardTool::distribution($level);
    $distributionOptions[] = [
        'value' => (string)$level,
        'label' => $level === 4 ? __('Any sharing group') : ($distributionLevels[$level] ?? (string)$level),
        'style' => ['badge' => $badge['icon'], 'css' => $badge['style']],
    ];
}
$children[] = [
    'type' => 'picker',
    'name' => 'distribution',
    'label' => __('Distribution'),
    'icon' => 'fas fa-share-nodes',
    'options' => $distributionOptions,
    'sub' => [
        'option' => '4',
        'name' => 'sharinggroup',
        'label' => __('Sharing group'),
        'source' => $baseurl . '/sharing_groups/pickerSearch',
        'exclude' => true,
        'resolved' => $filterLabels['sharinggroup'] ?? [],
        'hint' => __('Including a group keeps only events shared with it.'),
    ],
];
$children[] = [
    'type' => 'picker',
    'name' => 'published',
    'label' => __('Published'),
    'icon' => 'fas fa-upload',
    'options' => [
        ['value' => '1', 'label' => __('Published'), 'style' => ['icon' => 'fas fa-circle-check']],
        ['value' => '0', 'label' => __('Unpublished'), 'style' => ['icon' => 'fas fa-file-pen']],
    ],
];
$timePresets = [
    ['value' => '1d', 'label' => __('24h'), 'title' => __('last 24 hours')],
    ['value' => '7d', 'label' => __('7d'), 'title' => __('last 7 days')],
    ['value' => '30d', 'label' => __('30d'), 'title' => __('last 30 days')],
    ['value' => '90d', 'label' => __('90d'), 'title' => __('last 90 days')],
    ['value' => '365d', 'label' => __('1y'), 'title' => __('last year')],
];
$children[] = [
    'type' => 'time',
    'name' => 'time',
    'label' => __('Time'),
    'icon' => 'far fa-clock',
    'fields' => [
        ['name' => 'timestamp', 'label' => __('Changed')],
        ['name' => 'publish_timestamp', 'label' => __('Published'), 'aliases' => ['publishtimestamp']],
    ],
    'presets' => $timePresets,
];

if (!empty($show_user_button)) {
    $mine = strtolower((string)$filterState->get('email')) === strtolower($me['email']);
    $children[] = [
        'type' => 'button',
        'id' => 'ifp-my-events',
        'label' => __('My events'),
        'icon' => 'misp-icon misp-icon-user1 misp-simple',
        'class' => 'btn btn-outline-primary',
        'pressed' => $mine,
        'url' => $filterState->url(['email' => $mine ? null : $me['email']]),
    ];
}

// With the org picker, the reader's own org heads its list instead.
if (!empty($show_org_button) && !$canPickOrgs) {
    $ours = $filterState->get('org') === (string)$me['org_id'];
    $children[] = [
        'type' => 'button',
        'id' => 'ifp-org-events',
        'label' => __('Org events'),
        'icon' => 'misp-icon misp-icon-organisation misp-simple',
        'class' => 'btn btn-outline-primary',
        'pressed' => $ours,
        'url' => $filterState->url(['org' => $ours ? null : (string)$me['org_id']]),
    ];
}

$timeTitles = array_column($timePresets, 'title', 'value');
$timeDay = function ($value) {
    return ctype_digit($value) ? date('Y-m-d', (int)$value) : substr($value, 0, 10);
};
$timeLabel = function ($value) use ($timeTitles, $timeDay) {
    if (isset($timeTitles[$value])) {
        return $timeTitles[$value];
    }
    if (strpos($value, '|') !== false) {
        [$from, $to] = explode('|', $value, 2);
        return $from === '' || $from === '0'
            ? sprintf(__('until %s'), $timeDay($to))
            : $timeDay($from) . ' – ' . $timeDay($to);
    }
    if (preg_match('/^(\d+)([dhms])$/i', $value, $m)) {
        $units = ['d' => __('days'), 'h' => __('hours'), 'm' => __('minutes'), 's' => __('seconds')];
        return sprintf(__('last %s %s'), $m[1], $units[strtolower($m[2])]);
    }
    if (ctype_digit($value)) {
        return sprintf(__('since %s'), date('Y-m-d H:i', (int)$value));
    }
    if (preg_match('/^\d{4}-\d{2}-\d{2}/', $value)) {
        return sprintf(__('since %s'), $value);
    }
    return $value;
};
$threatLevels = null;
$chips = [
    'scope' => ['email'],
    'labels' => [
        'org' => __('Creator org'),
        'all' => __('Anything'),
        'attribute' => __('Attribute'),
        'value' => __('Attribute value'),
        'datefrom' => __('Date from'),
        'dateuntil' => __('Date until'),
        'tags' => __('Tags'),
        'sharinggroup' => __('Sharing group'),
        'analysis' => __('Analysis'),
        'threatlevel' => __('Threat level'),
        'hasproposal' => __('Proposals'),
        'timestamp' => __('Changed'),
        'publishtimestamp' => __('Published'),
        'publish_timestamp' => __('Published'),
        'firstpublished' => __('First published'),
        'pending' => __('Changes pending'),
        'is_extension' => __('Extension'),
        'is_extended' => __('Extended'),
        'minimal' => __('Minimal'),
    ],
    'values' => [
        'analysis' => array_map('strval', $analysisLevels ?? []),
        'threatlevel' => function ($value) use (&$threatLevels) {
            if ($threatLevels === null) {
                $threatLevels = ClassRegistry::init('ThreatLevel')->listThreatLevels();
            }
            return implode(', ', array_map(function ($piece) use ($threatLevels) {
                return ($piece[1] ? '≠ ' : '') . ($threatLevels[$piece[0]] ?? $piece[0]);
            }, IndexFilterState::pieces($value)));
        },
        'hasproposal' => ['1' => __('some'), '0' => __('none')],
        'pending' => function ($value) {
            return $value === '1' ? '' : __('none');
        },
        'is_extension' => ['1' => __('yes'), '0' => __('no')],
        'is_extended' => ['1' => __('yes'), '0' => __('no')],
        'timestamp' => $timeLabel,
        'publishtimestamp' => $timeLabel,
        'publish_timestamp' => $timeLabel,
        'firstpublished' => $timeLabel,
    ],
];
$statsHtml = isset($indexStats) ? $this->element('Events/index_stats', [
    'stats' => $indexStats,
    'state' => $filterState,
    'canPickOrgs' => $canPickOrgs,
]) : '';

/**
 * ==============================================================
 * Call the generic scaffold
 * ==============================================================
 *
 * Main parameters:
 *
 * - scaffold_data.data.data       : Main dataset
 * - scaffold_data.data.filter_bar    : Filter bar configuration
 * - scaffold_data.data.fields     : Column definitions
 * - index_url                     : Base URL for pagination / filters
 */

echo $this->element('genericElements/assetLoader', [
    'css' => ['org-tile', 'events-index-cards', 'events-index-table', 'intel-graph-thumbs'],
    'js' => ['events-index-cards', 'events-index-table', 'intel-graph-thumb', 'intel-graph-thumbs'],
]);

echo $this->OrgGrade->config($orgGrading ?? null);

printf(
    '<style class="te-colstyle">%s</style><div class="dk-index te-index" data-te="%s">',
    $hiddenRules ? implode(',', $hiddenRules) . '{display:none}' : '',
    h(json_encode($tableConfig))
);
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $events,
            // The grid itself is events-index-cards.css: auto-fill, 330px minimum.
            'cards_per_row' => 1,
            'card_element' => 'Events/index_card',
            'before_filter_bar' => $statsHtml,
            'filter_bar' => [
                'pull' => 'right',
                'children' => $children,
                'chips' => $chips,
                'apply' => 'close',
                'export' => 1,
                'delete' => '/delete',
                'mass_graph' => $canGraph,
            ],
            'fields' => $fields,
            'primary_id_path' => 'Event.id',
            'row_dblclick_url' => $baseurl . '/events/view/%id%',
            'table_class' => 'te-table',
            'row_class_callable' => function ($row) {
                return 'te-row';
            },
            'row_data_callable' => function ($row) {
                return ['event-id' => $row['Event']['id']];
            },
        ]
    ],
    'item_url' => '/events'
]);
echo '</div>';
