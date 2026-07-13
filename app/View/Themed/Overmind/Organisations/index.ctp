<?php
// Header section
$scopeTitles = [
    'local' => __('Local organisations'),
    'external' => __('Known remote organisations'),
    'all' => __('All organisations'),
];
$headerTitle = $scopeTitles[$scope] ?? __('Organisations');
$headerDescription = __('Organisations known to this instance, both local members and remote entities referenced in sharing groups.');

$headerActions = [];
if ($isSiteAdmin) {
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
        'name' => __('ID'),
        'sort' => 'Organisation.id',
        'data_path' => 'Organisation.id',
        'element' => 'id',
        'url' => $baseurl . '/organisations/view/%id%',
    ],
    [
        'name' => __('Name'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation',
        'element' => 'organisation',
    ],
    [
        'name' => __('UUID'),
        'sort' => 'Organisation.uuid',
        'data_path' => 'Organisation.uuid',
        'class' => 'quickSelect',
        'requirement' => $isSiteAdmin,
    ],
    [
        'name' => __('Description'),
        'data_path' => 'Organisation.description',
    ],
    [
        'name' => __('Nationality'),
        'sort' => 'Organisation.nationality',
        'element' => 'custom',
        'function' => function (array $row) {
            $name = trim($row['Organisation']['nationality'] ?? '');
            if ($name === '') {
                return '';
            }
            $code = $row['Organisation']['country_code'] ?? null;
            $flag = $code ? $this->Icon->countryFlag($code) . '&nbsp;' : '';
            return $flag . h($name);
        },
    ],
    [
        'name' => __('Sector'),
        'sort' => 'Organisation.sector',
        'data_path' => 'Organisation.sector',
    ],
    [
        'name' => __('Type'),
        'sort' => 'Organisation.type',
        'data_path' => 'Organisation.type',
    ],
    [
        'name' => __('Contacts'),
        'data_path' => 'Organisation.contacts',
    ],
    [
        'name' => __('Added by'),
        'sort' => 'created_by_email',
        'data_path' => 'Organisation.created_by_email',
        'requirement' => $isSiteAdmin,
    ],
    [
        'name' => __('Local'),
        'sort' => 'Organisation.local',
        'element' => 'custom',
        'function' => function (array $row) {
            $local = !empty($row['Organisation']['local']);
            return sprintf(
                '<span class="badge %s">%s</span>',
                $local ? 'text-bg-success' : 'text-bg-secondary',
                $local ? __('Local') : __('Remote')
            );
        },
    ],
    [
        'name' => __('Users'),
        'sort' => 'user_count',
        'data_path' => 'Organisation.user_count',
    ],
    [
        'name' => __('Restrictions'),
        'sort' => 'Organisation.restricted_to_domain',
        'data_path' => 'Organisation.restricted_to_domain',
        'array_implode_glue' => "\n",
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
                'type' => 'postLink',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/admin/organisations/delete/%id%',
                'class' => 'text-danger',
                'confirm' => __('Are you sure you want to delete the Organisation?'),
            ] : null,
        ])),
    ],
];

// Scope switch (local / known remote / all) mirrors the legacy top bar. Each is
// a fresh navigation; the search box below preserves the active scope.
$scopeButtons = [
    ['label' => __('Local organisations'), 'value' => 'local', 'url' => $baseurl . '/organisations/index/scope:local'],
    ['label' => __('Known remote organisations'), 'value' => 'external', 'url' => $baseurl . '/organisations/index/scope:external'],
    ['label' => __('All organisations'), 'value' => 'all', 'url' => $baseurl . '/organisations/index/scope:all'],
];
$filterChildren = [];
foreach ($scopeButtons as $button) {
    $filterChildren[] = [
        'type' => 'button',
        'label' => $button['label'],
        'url' => $button['url'],
        'class' => 'btn btn-sm ' . ($scope === $button['value'] ? 'btn-primary' : 'btn-outline-primary'),
    ];
}
$filterChildren[] = [
    'type' => 'search',
    'button' => __('Filter'),
    'placeholder' => __('Enter value to search'),
    'name' => 'searchall',
    'mode' => 'legacy',
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => $filterChildren,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/organisations'
]);
