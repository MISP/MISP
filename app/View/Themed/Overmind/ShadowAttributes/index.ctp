<?php
// Title of the index displayed in the header section
$headerTitle = __('Proposals');

// Description displayed under the title in the header section
$headerDescription = __('');

$headerActions = [];

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 */

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'ShadowAttribute.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'ShadowAttribute.id',
        'url' => $baseurl . '/events/view2/%id%',
        'element' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Proposed value'),
        'sort' => 'value',
        'data_path' => 'ShadowAttribute.value',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Category'),
        'sort' => 'category',
        'data_path' => 'ShadowAttribute.category',
        'element' => 'category',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Type'),
        'sort' => 'type',
        'data_path' => 'ShadowAttribute.type',
        'element' => 'type',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Proposal by'),
        'data_path' => 'Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Change requested'),
        'sort' => 'old_id',
        'data_path' => 'ShadowAttribute.old_id',
        'element' => 'boolean',
        'colors' => true,
        'class' => 'short',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Event'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id, Event.info',
        'element' => 'event',
        'org_data_path' => 'Event.Orgc',
        'url' => $baseurl . '/events/view2/%event_id%',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'timestamp',
        'data_path' => 'ShadowAttribute.timestamp',
        'element' => 'timestamp',
        'mode' => 'created',
        'class' => 'short',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'ShadowAttribute.event_id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View Event'),
                'icon' => 'eye',
                'url' => $baseurl . '/events/view2/%id%/focus:%focus%',
                'url_params_data_paths' => ['focus' => 'ShadowAttribute.uuid'],
            ],
        ],
    ],
];

/**
 * ==============================================================
 * Call the generic scaffold
 * ==============================================================
 *
 * The proposals index defaults to "All Events" (the controller sets
 * $all = 1 when no `all` named param is provided). The legacy
 * My Org's Events / All Events toggle is replaced by a single
 * "My org's events" button in the filter bar, mirroring the events
 * index: the button links to `all:0`, and the default (no filter) /
 * "Clear all" resets back to all events.
 */

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $shadowAttributes,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Enter value to search'),
                        'name' => 'searchall',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'button',
                        'label' => __('My org\'s events'),
                        'icon' => 'misp-icon misp-icon-organisation misp-simple',
                        'class' => 'btn btn-primary',
                        'url' => $baseurl . '/shadow_attributes/index/all:0',
                    ],
                ],
            ],
            'fields' => $fields,
            'primary_id_path' => 'ShadowAttribute.event_id',
        ]
    ],
    'item_url' => '/shadow_attributes'
]);
