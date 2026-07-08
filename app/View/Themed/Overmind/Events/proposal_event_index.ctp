<?php
// Title of the index displayed in the header section
$headerTitle = __('Events with Proposals');
$headerDescription = __('');
$headerActions = [];

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

/**
 * ==============================================================
 * Pre-processing
 * ==============================================================
 *
 * The controller exposes the contributing org ids per event in
 * $event['orgArray'] and a separate id => name map in $orgs. The
 * generic index field elements only receive the row, so we flatten
 * the contributors into a ready-to-render list of {id, name} on each
 * row (consumed by the 'org_list' field element).
 */
foreach ($events as $k => $event) {
    $contributors = [];
    foreach (($event['orgArray'] ?? []) as $orgId) {
        $contributors[] = [
            'id' => $orgId,
            'name' => $orgs[$orgId] ?? $orgId,
        ];
    }
    $events[$k]['ContributorOrgs'] = $contributors;
}

/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 */

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Event.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'Event.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Info'),
        'data_path' => 'Event',
        'element' => 'event_info',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Published'),
        'sort' => 'Event.published',
        'data_path' => 'Event.published',
        'element' => 'published',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Contributors'),
        'data_path' => 'ContributorOrgs',
        'element' => 'org_list',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Email'),
        'sort' => 'user_id',
        'data_path' => 'User.email',
        'requirement' => $isSiteAdmin,
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Created'),
        'data_path' => 'Event.date',
        'element' => 'timestamp',
        'mode' => 'created',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Proposals'),
        'data_path' => 'Event.proposal_count',
        'element' => 'count',
        'url' => $baseurl . '/events/view2/%id%#tab-attributes',
        'url_params_data_paths' => ['id' => 'Event.id'],
        'class' => 'short',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'ShadowAttribute.event_id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
        ],
    ],
];

/**
 * ==============================================================
 * Call the generic scaffold
 * ==============================================================
 */

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $events,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [],
            ],
            'fields' => $fields,
            'primary_id_path' => 'Event.id',
            'row_dblclick_url' => $baseurl . '/events/view2/%id%',
        ]
    ],
    'item_url' => '/events'
]);
