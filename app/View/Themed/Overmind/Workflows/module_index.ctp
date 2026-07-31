<?php

$this->set('headerTitle', __('Workflow modules'));
$this->set('headerDescription', __('The catalogue the workflow editor draws from. A disabled module does not appear on the canvas.'));
$this->set('headerActions', []);

$canToggle = !empty($isSiteAdmin);

$fields = [];

if ($canToggle) {
    $fields[] = [
        'element' => 'checkbox',
        'data_path' => 'id',
        'enable_path' => 'enabled',
        'card_section' => 'selector',
    ];
}

$fields = array_merge($fields, [
    [
        'name' => __('Module'),
        'sort' => 'name',
        'data_path' => 'name',
        'element' => 'module_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Type'),
        'sort' => 'module_type',
        'data_path' => 'module_type',
        'element' => 'trigger_scope',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'disabled',
        'data_path' => 'disabled',
        'element' => 'custom',
        // Not the shared `enabled` element: it early-returns on a falsy value,
        // so a disabled module would render an empty cell instead of a badge.
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
        'sort' => 'expect_misp_core_format',
        'data_path' => 'expect_misp_core_format',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('misp-module'),
        'sort' => 'is_misp_module',
        'data_path' => 'is_misp_module',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Custom'),
        'sort' => 'is_custom',
        'data_path' => 'is_custom',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
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
                // toggleModule($module_id, $enabled) — no trailing is_trigger
                // flag, so this hits the Redis set of enabled modules.
                'action_on' => '0',
                'action_off' => '1',
                'url' => $baseurl . '/workflows/toggleModule/%id%/%action%',
            ] : null,
            // [
            //     'type' => 'navigate',
            //     'label' => __('Module details'),
            //     'icon' => 'eye',
            //     'url' => $baseurl . '/workflows/moduleView/%id%',
            // ],
        ])),
    ],
]);

$filterBar = [
    'action' => 'moduleIndex',
    'pull' => 'right',
    'children' => [
        [
            'type' => 'search',
            'button' => __('Search'),
            'placeholder' => __('Search by module name'),
            'mode' => 'quickFilter',
        ],
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'label' => __('Type'),
                    'name' => 'type',
                    'options' => [
                        'action' => __('Action'),
                        'logic' => __('Logic'),
                        'all' => __('All'),
                        'custom' => __('Custom only'),
                    ],
                ],
                [
                    'type' => 'dropdown',
                    'label' => __('Kind'),
                    'name' => 'actiontype',
                    'options' => [
                        '' => __('All'),
                        'mispmodule' => __('misp-module'),
                        'blocking' => __('Blocking'),
                    ],
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
            ],
        ],
    ],
];
if ($canToggle) {
    $filterBar['enable'] = 1;
    $filterBar['enable_url'] = '/workflows/massToggleModule/1';
    $filterBar['disable_url'] = '/workflows/massToggleModule/0';
}
?>

<?php if (!empty($module_service_error)): ?>
    <div class="container-fluid">
        <div class="alert alert-warning d-flex align-items-start gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div>
                <strong><?= __('misp-modules action service is not reachable.') ?></strong>
                <?= __('Modules provided by that service will not be listed.') ?>
                <div class="small mt-1">
                    <?= __(
                        'Check that %s is enabled in the %s and that the service is up.',
                        '<code>Plugin.Action_services_enable</code>',
                        sprintf('<a href="%s">%s</a>', $baseurl . '/servers/serverSettings/Plugin', __('plugin settings'))
                    ) ?>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>

<?php if (!empty($errorWhileLoading)): ?>
    <div class="container-fluid">
        <div class="alert alert-danger d-flex align-items-start gap-2" role="alert">
            <i class="fas fa-circle-exclamation mt-1"></i>
            <div>
                <strong><?= __n('A module failed to load.', 'Some modules failed to load.', count($errorWhileLoading)) ?></strong>
                <ul class="mb-0 mt-1 small">
                    <?php foreach ($errorWhileLoading as $filepath => $message): ?>
                        <li><code><?= h($filepath) ?></code>: <?= h($message) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
<?php endif; ?>

<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => $filterBar,
            'fields' => $fields,
            'primary_id_path' => 'id',
            'row_dblclick_url' => $baseurl . '/workflows/moduleView/%id%',
        ]
    ],
    'item_url' => '/workflows'
]);
