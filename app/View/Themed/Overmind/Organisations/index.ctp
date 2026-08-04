<?php

$headerTitle =  __("Instance's Organisations");
$headerDescription = __('Organisations known to this instance, both local members and remote entities referenced in sharing groups.');

$headerActions = [];
if ($isSiteAdmin) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Merge organisations'),
        'icon' => 'code-merge',
        'class' => 'btn btn-outline-danger',
        'url' => $baseurl . '/admin/organisations/merge'
    ];
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add organisation'),
        'icon' => 'plus',
        'url' => $baseurl . '/admin/organisations/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Organisation.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Organisation.id',
        'data_path' => 'Organisation.id',
        'element' => 'id',
        'url' => $baseurl . '/organisations/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('UUID'),
        'sort' => 'Organisation.uuid',
        'data_path' => 'Organisation.uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/organisations/view/%id%',
        'requirement' => $isSiteAdmin,
        'card_section' => 'top',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Name'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'show_description' => true,
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Nationality'),
        'sort' => 'Organisation.nationality',
        'data_path' => 'Organisation.nationality',
        'element' => 'analyst_language',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Sector'),
        'sort' => 'Organisation.sector',
        'data_path' => 'Organisation.sector',
        'element' => 'labeled_text',
        'icon' => 'industry',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Type'),
        'sort' => 'Organisation.type',
        'data_path' => 'Organisation.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Contacts'),
        'data_path' => 'Organisation.contacts',
        'element' => 'labeled_text',
        'icon' => 'address-book',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Added by'),
        'sort' => 'created_by_email',
        'data_path' => 'Organisation.created_by_email',
        'element' => 'labeled_text',
        'icon' => 'user-plus',
        'requirement' => $isSiteAdmin,
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Local'),
        'sort' => 'Organisation.local',
        'element' => 'custom',
        'function' => function (array $row) {
            $local = !empty($row['Organisation']['local']);
            return sprintf(
                '<span class="badge %s">%s</span>',
                $local ? 'text-bg-success' : 'text-bg-danger',
                $local ? __('Local') : __('Remote')
            );
        },
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Users'),
        'sort' => 'user_count',
        'data_path' => 'Organisation.user_count',
        'element' => 'custom',
        'function' => function (array $row) use ($baseurl, $isSiteAdmin, $me) {
            $count = (int) Hash::get($row, 'Organisation.user_count');
            $orgId = Hash::get($row, 'Organisation.id');
            $badge = sprintf(
                '<span class="badge %s rounded-pill px-3 py-2 shadow-sm"><i class="fas fa-layer-group me-1"></i>%s</span>',
                $count === 0 ? 'bg-secondary' : 'bg-primary',
                h($count)
            );
            $canFilterUsers = !empty($isSiteAdmin)
                || (!empty($me['Role']['perm_admin']) && $orgId !== null && $orgId == ($me['org_id'] ?? null));
            if ($canFilterUsers && $count > 0 && $orgId !== null) {
                return sprintf(
                    '<a href="%s/admin/users/index/searchorg:%s" class="text-decoration-none" title="%s">%s</a>',
                    h($baseurl),
                    h($orgId),
                    h(__('View users in this organisation')),
                    $badge
                );
            }
            return $badge;
        },
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Restrictions'),
        'sort' => 'Organisation.restricted_to_domain',
        'data_path' => 'Organisation.restricted_to_domain',
        'element' => 'domain_restrictions',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Organisation.id',
        'actions' => array_values(array_filter([
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/organisations/view/%id%',
            ],
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/admin/organisations/edit/%id%',
            ] : null,
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'size' => 'sm',
                'url' => $baseurl . '/admin/organisations/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ])),
    ],
];


$scaffoldFilterBar = [
    'children' => [
        [
            'type' => 'search',
            'mode' => 'legacy',
            'name' => 'searchall',
            'placeholder' => __('Enter value to search'),
        ],
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'name' => 'scope',
                    'label' => __('Local'),
                    'options' => [
                        'all'      => __('All organisations'),
                        'local'    => __('Local organisations'),
                        'external' => __('Known remote organisations'),
                    ],
                ],
            ]
        ],
    ],
];

if ($isSiteAdmin) {
    $scaffoldFilterBar['delete'] = '/deleteSelection';
    $scaffoldFilterBar['delete_url'] = '/admin/organisations/deleteSelection';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Organisation.id',
            'row_dblclick_url' => $baseurl . '/organisations/view/%id%',
            'filter_bar' => $scaffoldFilterBar,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/organisations'
]);
