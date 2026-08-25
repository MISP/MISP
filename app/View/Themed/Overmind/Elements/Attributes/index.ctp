<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


// Temporary fix to avoid errors as these variables are defined in AttributesController
$categoryOptions = isset($categoryOptions) ? $categoryOptions : null;
$typeOptions = isset($typeOptions) ? $typeOptions : null;
$orgOptions = isset($orgOptions) ? $orgOptions : null;
$tagOptions = isset($tagOptions) ? $tagOptions : null;
$galaxyOptions = isset($galaxyOptions) ? $galaxyOptions : null;

/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 *
 * Possible fields for each entry:
 *
 * - name           : Label displayed in the table
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
 * - type           : modal | navigate | toggle | copy | divider
 * - label          : Displayed text
 * - label_on/off   : Text for toggle
 * - icon           : FontAwesome icon
 * - icon_on/off    : Toggle icon
 * - url            : URL (supports %id% and %action%)
 * - data_path      : Value to copy (for type = copy)
 * - copy_message   : Toast text shown after copy (for type = copy)
 * - class          : CSS class
 * - requirement    : Permission check function
 * - state_path     : Path to the boolean value (toggle)
 */

$firstRow   = !empty($attributes) ? reset($attributes) : [];
$model      = !empty($firstRow['Attribute']) ? 'Attribute' : null;
$_canModify = !empty($mayModify);
$_canPropose = !empty($me['Role']['perm_add']);
$_canAnalystData = !empty($me['Role']['perm_analyst_data']);
// Enrichment / Cortex expansion (misp-modules): the "Enrich" actions are only
// offered when the matching services plugin is enabled and the user can add data.
$_enrichmentEnabled = (bool)Configure::read('Plugin.Enrichment_services_enable');
$_cortexEnabled = (bool)Configure::read('Plugin.Cortex_services_enable');
// Analyst data is only attached to attributes in the event view (fetchPaginatedAttributes).
$inEventView = empty($show_event_id) && !empty($event['Event']['id']);

$path = function($field) use ($model) {
    if (empty($model)) return $field;
    if (empty($field)) return $model;
    return $model . '.' . $field;
};

$canTagAttr = false;
if (empty($show_event_id) && !empty($event['Event']['id'])) {
    $canTagAttr = $this->Acl->canModifyTag($event);
}

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Attribute.id',
        'card_section' => 'selector',
    ]
];

if (!empty($show_event_id)) {
    $fields[] = [
        'name' => __('Event ID'),
        'sort' => $path('event_id'),
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $baseurl . '/events/view2/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ];
}

$fields = array_merge($fields, [
    [
        'name' => __('Distribution'),
        'data_path' => $path('distribution'),
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Value'),
        'data_path' => $path(''),
        'element' => 'attribute_value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Category'),
        'sort' => $path('category'),
        'data_path' => $path('category'),
        'element' => 'category',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => $path('type'),
        'data_path' => $path('type'),
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
]);

if (!empty($show_event_id)) {
    $fields = array_merge($fields, [
    [
        'name' => __('Creator Org'),
        'sort' => 'Event.Orgc.name',
        'data_path' => 'Event.Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Event.Org.name',
        'data_path' => 'Event.Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card']
    ]
    ]);
}

$fields = array_merge($fields, [
    [
        'name' => __('Tags'),
        'data_path' => $path('AttributeTag'),
        'element' => 'tag_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card'],
        'add_tag' => $canTagAttr,
        'add_tag_url' => $baseurl . '/attributes/editAttributeTags/%id%',
        'add_tag_id_path' => $path('id'),
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => $path('Galaxy'),
        'element' => 'galaxy',
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card'],
        'add_galaxy' => $canTagAttr,
        'add_galaxy_url' => $baseurl . '/attributes/editAttributeGalaxies/%id%',
        'add_galaxy_id_path' => $path('id'),
    ],
    [
        'name' => __('IDS'),
        'data_path' => $path('to_ids'),
        'element' => 'ids',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Correlate'),
        'data_path' => $path('disable_correlation'),
        'element' => 'correlate',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Related Events'),
        'element' => 'relatedEvents',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Feed hits'),
        'element' => 'feedHits',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Last Modified'),
        'data_path' => $path('timestamp'),
        'element' => 'timestamp',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Sightings'),
        'element' => 'sightings',
        'sightings' => isset($sightingsData) ? $sightingsData : ['data' => [], 'csv' => []],
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Analyst data'),
        'element' => 'analyst_data_badges',
        'note_path' => $path('Note'),
        'opinion_path' => $path('Opinion'),
        'relationship_path' => $path('Relationship'),
        'relationship_inbound_path' => $path('RelationshipInbound'),
        'uuid_path' => $path('uuid'),
        'object_type' => 'Attribute',
        'requirement' => $inEventView,
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Attribute.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'copy',
                'label' => __('Copy UUID'),
                'icon' => 'copy',
                'data_path' => $path('uuid'),
                'copy_message' => __('UUID copied to clipboard'),
            ],
            [
                'type' => 'divider',
                'requirement' => function($row) use ($inEventView, $_canAnalystData) {
                    return $inEventView && $_canAnalystData && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Add note'),
                'icon' => 'misp-icon misp-icon-analyst-note misp-simple',
                'url' => $baseurl . '/analystData/add/Note/%uuid%/Attribute',
                'url_params_data_paths' => ['uuid' => $path('uuid')],
                'requirement' => function($row) use ($inEventView, $_canAnalystData) {
                    return $inEventView && $_canAnalystData && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Add opinion'),
                'icon' => 'misp-icon misp-icon-analyst-opinion misp-simple',
                'url' => $baseurl . '/analystData/add/Opinion/%uuid%/Attribute',
                'url_params_data_paths' => ['uuid' => $path('uuid')],
                'requirement' => function($row) use ($inEventView, $_canAnalystData) {
                    return $inEventView && $_canAnalystData && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Add relationship'),
                'icon' => 'diagram-project',
                'url' => $baseurl . '/analystData/add/Relationship/%uuid%/Attribute',
                'url_params_data_paths' => ['uuid' => $path('uuid')],
                'requirement' => function($row) use ($inEventView, $_canAnalystData) {
                    return $inEventView && $_canAnalystData && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'divider',
                'requirement' => function($row) use ($_canModify, $_enrichmentEnabled, $_cortexEnabled) {
                    return $_canModify && ($_enrichmentEnabled || $_cortexEnabled) && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Enrich'),
                'icon' => 'fas fa-wand-magic-sparkles text-enrichment',
                'url' => $baseurl . '/events/queryEnrichment/%id%/0/Enrichment/Attribute',
                'requirement' => function($row) use ($_canModify, $_enrichmentEnabled) {
                    return $_canModify && $_enrichmentEnabled && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Enrich (Cortex)'),
                'icon' => 'eye',
                'url' => $baseurl . '/events/queryEnrichment/%id%/0/Cortex/Attribute',
                'requirement' => function($row) use ($_canModify, $_cortexEnabled) {
                    return $_canModify && $_cortexEnabled && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Propose change'),
                'icon' => 'comment-dots',
                'url' => $baseurl . '/shadow_attributes/edit/%id%',
                'requirement' => function($row) use ($_canPropose) {
                    return  $_canPropose && empty($row['is_proposal']) && empty($row['deleted']);
                }
            ],
            [
                'type' => 'divider',
                'requirement' => function($row) use ($_canModify) {
                    return $_canModify && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/attributes/edit/%id%',
                'requirement' => function($row) use ($_canModify) {
                    return $_canModify && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Restore'),
                'icon' => 'rotate-left',
                'url' => $baseurl . '/attributes/restore/%id%',
                'class' => 'text-success',
                'requirement' => function($row) use ($_canModify) {
                    return $_canModify && !empty($row['deleted']) && empty($row['is_proposal']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/attributes/delete/%id%',
                'class' => 'text-danger',
                'requirement' => function($row) use ($_canModify) {
                    return $_canModify && empty($row['deleted']) && empty($row['is_proposal']);
                }
            ]
        ]
    ]
]);



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
 * - item_url                     : Base URL for pagination / filters
 */

$children = [
    [
        'type' => 'search',
        'button' => 'Search',
        "placeholder" => "Filter by attribute value"
    ]
];

if (!empty($show_filters)) {
    $children = array_merge($children, [
        [
            'type' => 'button',
            'label' => __('My attributes'),
            'icon' => 'misp-icon misp-icon-user1 misp-simple',
            'class' => 'btn btn-primary',
            'url' => $baseurl . '/attributes/index/searchemail:' . urlencode($me['email'])
        ],
        [
            'type' => 'button',
            'label' => __('Org attributes'),
            'icon' => 'misp-icon misp-icon-organisation misp-simple',
            'class' => 'btn btn-primary',
            'url' => $baseurl . '/attributes/index/searchorg:' . urlencode($me['org_id'])
        ]
    ]);
}

if (empty($show_event_id) && !empty($event['Event']['id'])) {
    // Event view: only category and type are supported by viewAttributes
    $children = array_merge($children, [
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'label' => __('Category'),
                    'name' => 'category',
                    'options' => ['' => __('All')] + ($categoryOptions ?? [])
                ],
                [
                    'type' => 'dropdown',
                    'label' => __('Type'),
                    'name' => 'type',
                    'options' => ['' => __('All')] + ($typeOptions ?? [])
                ],
            ]
        ]
    ]);
} else {
    $children = array_merge($children, [
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'label' => __('Category'),
                    'name' => 'category',
                    'options' => $categoryOptions ?? []
                ],
                [
                    'type' => 'dropdown',
                    'label' => __('Type'),
                    'name' => 'type',
                    'options' => $typeOptions ?? []
                ],
                [
                    'type' => 'dropdown',
                    'label' => __('Creator Org'),
                    'name' => 'org',
                    'options' => $orgOptions ?? []
                ],
                [
                    'type' => 'dropdown',
                    'label' => __('Tags'),
                    'name' => 'tag',
                    'options' => $tagOptions ?? []
                ],
                [
                    'type' => 'dropdown',
                    'label' => __('Galaxy'),
                    'name' => 'galaxy',
                    'options' => $galaxyOptions ?? []
                ]
            ]
        ]
    ]);
}

if (empty($show_event_id) && !empty($event['Event']['id'])) {
    $attrEventId     = $event['Event']['id'];
    $namedParams     = $this->request->params['named'] ?? [];
    $currentDeleted  = (int)($namedParams['deleted'] ?? 0);
    $currentProposal = (int)($namedParams['proposal'] ?? 0);
    $toggleDeleted   = $currentDeleted ? 0 : 1;
    $toggleProposal  = $currentProposal ? 0 : 1;
    $attrBaseUrl     = $baseurl . '/events/viewAttributes/' . $attrEventId;

    // Fallback hrefs (real toggles are handled by view_attributes.ctp)
    $deletedUrl  = $attrBaseUrl
        . ($toggleDeleted ? '/deleted:' . $toggleDeleted : '')
        . ($currentProposal ? '/proposal:' . $currentProposal : '');
    $proposalUrl = $attrBaseUrl
        . ($currentDeleted ? '/deleted:' . $currentDeleted : '')
        . ($toggleProposal ? '/proposal:' . $toggleProposal : '');

    $children[] = [
        'type'  => 'button',
        'url'   => $proposalUrl,
        'class' => 'btn attr-proposal-toggle ' . ($currentProposal ? 'btn-warning' : 'btn-outline-warning'),
        'icon'  => 'fas fa-comment-dots',
        'label' => __('Proposals') . (!empty($proposalCount) ? ' (' . (int)$proposalCount . ')' : ''),
    ];

    $children[] = [
        'type'  => 'button',
        'url'   => $deletedUrl,
        'class' => 'btn attr-deleted-toggle ' . ($currentDeleted ? 'btn-danger' : 'btn-outline-danger'),
        'icon'  => 'fas fa-trash',
        'label' => __('Deleted') . (!empty($deletedCount) ? ' (' . (int)$deletedCount . ')' : ''),
    ];
}


echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $attributes,
            'primary_id_path' => $path('id'),
            'row_class_callable' => function($row) {
                if (!empty($row['is_proposal'])) {
                    return 'attr-proposal-row';
                }
                return !empty($row['deleted']) ? 'attr-deleted' : '';
            },
            'filter_bar' => [
                'pull' => 'right',
                'children' => $children,
                'soft_delete' => '/deleteSelection',
                // 'mass_edit' => 1,
                // 'mass_tag' => 1,
                // 'mass_local_tag' => 1,
                // 'mass_cluster' => 1,
                // 'mass_local_cluster' => 1,
                // 'mass_object' => 1,
                // 'mass_relationship' =>1,
                // 'mass_sighting' =>1,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/attributes'
]);

?>