<?php

$this->set('headerTitle', __('Triggers'));
$this->set('headerDescription', __('Hooks MISP calls on its own. Enable one, then attach the workflow that should listen to it.'));

$headerActions = [];
$this->set('headerActions', $headerActions);

$canToggle = !empty($isSiteAdmin);

$triggerOverhead = [
    1 => ['class' => 'success', 'text' => __('low')],
    2 => ['class' => 'warning', 'text' => __('medium')],
    3 => ['class' => 'danger',  'text' => __('high')],
];


$fields =  [
    [
        'element' => 'checkbox',
        'data_path' => 'id',
        'enable_path' => 'enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('Trigger'),
        'sort' => 'name',
        'data_path' => 'name',
        'element' => 'trigger_name',
        // Full scope list so the per-scope tint is stable under filtering.
        'scopes' => $scopes,
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Scope'),
        'sort' => 'scope',
        'data_path' => 'scope',
        'element' => 'trigger_scope',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Overhead'),
        'sort' => 'trigger_overhead',
        'data_path' => 'trigger_overhead',
        'element' => 'custom',
        'function' => function ($row) use ($triggerOverhead) {
            $level = Hash::get($row, 'trigger_overhead');
            if (empty($level) || empty($triggerOverhead[$level])) {
                return '';
            }
            $disabled = !empty(Hash::get($row, 'disabled'));
            $message = Hash::get($row, 'trigger_overhead_message');
            $hint = '';
            if (!empty($message)) {
                $hint = sprintf(
                    ' <i class="fas fa-circle-question text-muted" title="%s"></i>',
                    h(($disabled ? '[' . __('Trigger not enabled') . '] ' : '') . $message)
                );
            }
            return sprintf(
                '<span class="badge rounded-pill %s">%s</span>%s',
                $disabled ? 'text-bg-secondary' : 'text-bg-' . $triggerOverhead[$level]['class'],
                h($triggerOverhead[$level]['text']),
                $hint
            );
        },
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'disabled',
        'data_path' => 'disabled',
        'element' => 'custom',
        // Not the shared `enabled` element: it early-returns on a falsy value,
        // so a disabled trigger would render an empty cell instead of a badge.
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
        'name' => __('Blocking'),
        'sort' => 'blocking',
        'data_path' => 'blocking',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Core format'),
        'sort' => 'misp_core_format',
        'data_path' => 'misp_core_format',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Workflow'),
        'data_path' => 'Workflow.counter',
        'element' => 'custom',
        'function' => function ($row) use ($baseurl) {
            $workflowId = Hash::get($row, 'Workflow.id');
            $workflowUuid = Hash::get($row, 'Workflow.uuid');
            if (empty($workflowId)) {
                return sprintf('<span class="text-muted small">%s</span>', __('none yet'));
            }
            return sprintf(
                '<a class="text-decoration-underline fw-semibold" href="%s/workflows/index/quickFilter:%s">#%s</a>'
                    . '<span class="text-muted small ms-2">%s</span>',
                h($baseurl),
                h($workflowUuid),
                h($workflowId),
                h(__('%s runs', (int)Hash::get($row, 'Workflow.counter')))
            );
        },
        'card_section' => 'links',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Debug'),
        'data_path' => 'Workflow.debug_enabled',
        'element' => 'debug_enabled',
        // Triggers with no workflow attached have no debug state to show.
        'empty_text' => __('no workflow'),
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
            $canToggle ? [
                'type' => 'toggle',
                'label_on' => __('Disable'),
                'label_off' => __('Enable'),
                'icon_on' => 'stop',
                'icon_off' => 'play',
                'state_path' => 'enabled',
                'action_on' => '0/1',
                'action_off' => '1/1',
                // toggleModule($module_id, $enabled, $is_trigger) — the trailing
                // /1 flags this as a trigger rather than a workflow module.
                'url' => $baseurl . '/workflows/toggleModule/%id%/%action%',
            ] : null,
            [
                'type' => 'navigate',
                'label' => __('Edit associated workflow'),
                'icon' => 'code',
                'url' => $baseurl . '/workflows/editor/%id%',
            ],
            // [
            //     'type' => 'navigate',
            //     'label' => __('Trigger details'),
            //     'icon' => 'eye',
            //     'url' => $baseurl . '/workflows/moduleView/%id%',
            // ],
            [
                'type' => 'navigate',
                'label' => __('Execution logs'),
                'icon' => 'rectangle-list',
                'url' => $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow/model_id:%workflow_id%',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
                'requirement' => function ($row) {
                    return !empty(Hash::get($row, 'Workflow.id'));
                },
            ],
            /*
             * Debug mode belongs to the *workflow*, not the trigger, so both
             * entries need one to exist. Two mutually exclusive actions rather
             * than a `toggle`: that type renders a postLink, and this endpoint
             * answers a confirmation modal first.
             */
            $canToggle ? [
                'type' => 'modal',
                'label' => __('Enable debug'),
                'icon' => 'bug',
                'size' => 'sm',
                'url' => $baseurl . '/workflows/toggleDebugMode/%workflow_id%/1',
                'url_params_data_paths' => ['workflow_id' => 'Workflow.id'],
                'requirement' => function ($row) {
                    return !empty(Hash::get($row, 'Workflow.id'))
                        && empty(Hash::get($row, 'Workflow.debug_enabled'));
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
                    return !empty(Hash::get($row, 'Workflow.id'))
                        && !empty(Hash::get($row, 'Workflow.debug_enabled'));
                },
            ] : null,
        ])),
    ],
];


$scopeOptions = ['' => __('All scopes')];
foreach ($scopes as $scope) {
    $scopeOptions[$scope] = $scope;
}

$filterBar = [
    'action' => 'triggers',
    'pull' => 'right',
    'children' => [
        [
            'type' => 'search',
            'button' => __('Search'),
            'placeholder' => __('Search by trigger name'),
            'mode' => 'quickFilter',
        ],
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'label' => __('Scope'),
                    'name' => 'scope',
                    'options' => $scopeOptions,
                ],
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
                [
                    'type' => 'dropdown',
                    'label' => __('Blocking'),
                    'name' => 'blocking',
                    'options' => [
                        '' => __('All'),
                        '1' => __('Blocking only'),
                        '0' => __('Non-blocking only'),
                    ],
                ],
            ],
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
            'primary_id_path' => 'id',
            //'row_dblclick_url' => $baseurl . '/workflows/editor/%id%',
        ]
    ],
    'item_url' => '/workflows'
]);
