<?php
// Title of the index displayed in the header section
$headerTitle = __('Delegations');

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
        'data_path' => 'EventDelegation.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'EventDelegation.id',
        'url' => '#',
        'element' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Requester'),
        'data_path' => 'EventDelegation.RequesterOrg',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Recipient'),
        'data_path' => 'EventDelegation.Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Message'),
        'sort' => 'value',
        'data_path' => 'EventDelegation.message',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Event'),
        'data_path' => 'EventDelegation.Event.id, EventDelegation.Event.info',
        'element' => 'event',
        'url' => $baseurl . '/events/view2/%event_id%',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'EventDelegation.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'modal',
                'url' => $baseurl . '/event_delegations/view/%id%',
                'icon' => 'gavel',
                'label' => __('Review request'),
                'size' => 'md',
            ],
        ],
    ],
];

/**
 * ==============================================================
 * Call the generic scaffold
 * ==============================================================
 *
 * The index defaults to the "pending" context (requests where our org is
 * the recipient). The "Issued requests" filter-bar button links to
 * `context:issued` (requests our org has sent out); "Clear all" on the
 * resulting filter badge resets back to the default pending view.
 */

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $delegation_requests,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Enter value to search'),
                        'name' => 'value',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'button',
                        'url' => $baseurl . '/event_delegations/index/context:issued',
                        'class' => 'btn btn-outline-primary',
                        'icon' => 'fas fa-paper-plane me-1',
                        'label' => __('Issued requests'),
                    ],
                ],
            ],
            'fields' => $fields,
            'primary_id_path' => 'EventDelegation.event_id',
        ]
    ],
    'item_url' => '/event_delegations'
]);
