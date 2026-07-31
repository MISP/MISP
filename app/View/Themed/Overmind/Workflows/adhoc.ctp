<?php

$this->set('headerTitle', __('Ad-hoc workflows'));
$this->set('headerDescription', __('Workflows with no core hook: you run them yourself, or another workflow calls them.'));

$canToggle = !empty($isSiteAdmin);

$headerActions = [];
if ($canToggle) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add ad-hoc workflow'),
        'icon' => 'plus',
        'url' => $baseurl . '/workflows/add',
    ];
}
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'id',
        'enable_path' => 'enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Workflow.id',
        'data_path' => 'Workflow.id',
        'element' => 'id',
        //'url' => $baseurl . '/workflows/editor/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Name'),
        'sort' => 'Workflow.name',
        'data_path' => 'Workflow.name, Workflow.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Data input'),
        'sort' => 'trigger_scope',
        'data_path' => 'trigger_scope',
        'element' => 'trigger_scope',
        'empty_text' => __('not configured'),
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Search filters'),
        'data_path' => 'trigger_filters',
        'element' => 'custom',
        // The json element always draws its bordered <pre>, which turns "no
        // filters" into a box containing `[]` on every unconfigured row.
        'function' => function ($row, $viewMode = 'table') {
            $filters = Hash::get($row, 'trigger_filters');
            if (is_string($filters)) {
                $decoded = json_decode($filters, true);
                $filters = $decoded === null ? $filters : $decoded;
            }
            if (empty($filters)) {
                return sprintf('<span class="text-muted">%s</span>', '&ndash;');
            }
            return $this->element('genericElementsBS5/IndexTable/Fields/json', [
                'row' => $row,
                'field' => ['data_path' => 'trigger_filters'],
                'viewMode' => $viewMode,
            ]);
        },
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Run counter'),
        'data_path' => 'Workflow.counter',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'disabled',
        'data_path' => 'disabled',
        'element' => 'custom',
        // Not the shared `enabled` element: it early-returns on a falsy value,
        // so a disabled workflow would render an empty cell instead of a badge.
        'function' => function ($row, $viewMode = 'table') {
            $enabled = empty(Hash::get($row, 'disabled'));
            return $this->element('genericElementsBS5/Badges/boolean', [
                'boolean' => $enabled,
                'full' => $viewMode === 'card',
                'true' => __('Enabled'),
                'false' => __('Disabled'),
                'trueColor' => 'success',
                'falseColor' => 'danger',
                'trueIcon' => 'fa-check-circle',
                'falseIcon' => 'fa-times-circle',
            ]);
        },
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Debug'),
        'data_path' => 'Workflow.debug_enabled',
        'element' => 'debug_enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Last update'),
        'data_path' => 'Workflow.timestamp',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            /*
             * Running with no payload only makes sense when the trigger fetches
             * its own data, which is the Events RestSearch scope — the same gate
             * the legacy index applies.
             */
            $canToggle ? [
                'type' => 'modal',
                'label' => __('Run workflow'),
                'icon' => 'play-circle',
                'url' => $baseurl . '/workflows/executeWorkflow/%workflow_id%',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
                'requirement' => function ($row) {
                    return Hash::get($row, 'trigger_scope') === 'events';
                },
            ] : null,
            $canToggle ? [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'stop',
                'icon_off' => 'play',
                'state_path' => 'enabled',
                'action_on' => '0/1',
                'action_off' => '1/1',
                // toggleModule() routes an ad-hoc id to toggleAdHocWorkflow(),
                // which flips a Redis set rather than a server setting.
                'url' => $baseurl . '/workflows/toggleModule/%id%/%action%',
            ] : null,
            [
                'type' => 'navigate',
                'label' => __('Open in editor'),
                'icon' => 'code',
                'url' => $baseurl . '/workflows/editor/%workflow_id%',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
            ],
            $canToggle ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/workflows/edit/%workflow_id%',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
            ] : null,
            [
                'type' => 'navigate',
                'label' => __('Execution logs'),
                'icon' => 'rectangle-list',
                'url' => $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow/model_id:%workflow_id%',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
            ],
            $canToggle ? [
                'type' => 'modal',
                'label' => __('Enable debug'),
                'icon' => 'bug',
                'size' => 'sm',
                'url' => $baseurl . '/workflows/toggleDebugMode/%workflow_id%/1',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
                'requirement' => function ($row) {
                    return empty(Hash::get($row, 'Workflow.debug_enabled'));
                },
            ] : null,
            $canToggle ? [
                'type' => 'modal',
                'label' => __('Disable debug'),
                'icon' => 'bug-slash',
                'size' => 'sm',
                'url' => $baseurl . '/workflows/toggleDebugMode/%workflow_id%/0',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
                'requirement' => function ($row) {
                    return !empty(Hash::get($row, 'Workflow.debug_enabled'));
                },
            ] : null,
            $canToggle ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/workflows/deleteSelection/%workflow_id%',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
            ] : null,
        ])),
    ],
];

$scopeOptions = ['' => __('All')];
foreach ($dataInputScopes as $scope) {
    $scopeOptions[$scope] = $scope;
}

$filterBar = [
    'action' => 'adhoc',
    'pull' => 'right',
    'children' => [
        [
            'type' => 'search',
            'button' => __('Search'),
            'placeholder' => __('Search by workflow name'),
            'mode' => 'quickFilter',
        ],
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => array_values(array_filter([
                [
                    'type' => 'dropdown',
                    'label' => __('Enabled'),
                    'name' => 'enabled',
                    'options' => [
                        '' => __('All'),
                        '1' => __('Enabled'),
                        '0' => __('Disabled'),
                    ],
                ],
                count($scopeOptions) > 1 ? [
                    'type' => 'dropdown',
                    'label' => __('Data input scope'),
                    'name' => 'trigger_scope',
                    'options' => $scopeOptions,
                ] : null,
            ])),
        ],
    ],
];
if ($canToggle) {
    $filterBar['enable'] = 1;
    $filterBar['enable_url'] = '/workflows/massToggleTrigger/1';
    $filterBar['disable_url'] = '/workflows/massToggleTrigger/0';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => $filterBar,
            'fields' => $fields,
            'primary_id_path' => 'Workflow.id',
            //'row_dblclick_url' => $baseurl . '/workflows/editor/%id%',
        ]
    ],
    'item_url' => '/workflows'
]);
