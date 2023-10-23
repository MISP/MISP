<?php
    $warning_message_title = __('This trigger might have a negative impact on performance');
    $trigger_overhead_mapping = [
        1 => [
            'class' => 'success',
            'text' => __('low'),
        ],
        2 => [
            'class' => 'warning',
            'text' => __('medium'),
        ],
        3 => [
            'class' => 'important',
            'text' => __('high'),
        ],
    ];

    $scopesFilters = [];
    foreach ($scopes as $scope) {
        $scopesFilters[] = [
            'url' => $baseurl . sprintf('/workflows/triggers/scope:%s', h($scope)),
            'text' => h($scope),
            'active' => !empty($filters['scope']) && $filters['scope'] == $scope,
        ];
    }

    $fields = [
        [
            'name' => __('Trigger name'),
            'sort' => 'name',
            'data_path' => 'name',
            'element' => 'custom',
            'class' => 'bold',
            'function' => function ($row) {
                return sprintf('<i class="fa-fw %s"></i> %s', $this->FontAwesome->getClass($row['icon']), h($row['name']));
            }
        ],
        [
            'name' => __('Scope'),
            'data_path' => 'scope',
            'sort' => 'scope',
        ],
        [
            'name' => __('Trigger overhead'),
            'data_path' => 'trigger_overhead',
            'sort' => 'trigger_overhead',
            'element' => 'custom',
            'function' => function ($row) use ($trigger_overhead_mapping) {
                return empty($row['trigger_overhead'])  ? '' :
                    sprintf(
                        '<span class="label %s">%s %s</span>',
                        !empty($row['disabled']) ? '' : 'label-' . $trigger_overhead_mapping[$row['trigger_overhead']]['class'],
                        h($trigger_overhead_mapping[$row['trigger_overhead']]['text']),
                        empty($row['trigger_overhead_message']) ? '' :
                            sprintf(
                                '<i class="fa-fw %s" title="%s" data-placement="right" data-toggle="tooltip"></i>',
                                $this->FontAwesome->getClass('question-circle'),
                                sprintf('%s%s',
                                    !empty($row['disabled']) ? sprintf('[%s]' . PHP_EOL, __('Trigger not enabled')) : '',
                                    h($row['trigger_overhead_message'])
                                )
                            )
                    );
            }
        ],
        [
            'name' => __('Description'),
            'data_path' => 'description',
        ],
        [
            'name' => __('Run counter'),
            'sort' => 'Workflow.counter',
            'data_path' => 'Workflow.counter',
        ],
        [
            'name' => __('Blocking Workflow'),
            'class' => 'short',
            'sort' => 'blocking',
            'data_path' => 'blocking',
            'element' => 'boolean',
            'colors' => true,
            'title' => __('Can the workflow block the execution of the operation calling the trigger')
        ],
        [
            'name' => __('MISP Core format'),
            'class' => 'short',
            'sort' => 'misp_core_format',
            'data_path' => 'misp_core_format',
            'element' => 'boolean',
            'colors' => true,
            'title' => __('Is the data compliant with the MISP Core format.')
        ],
        [
            'name' => __('Workflow ID'),
            'sort' => 'Workflow.id',
            'data_path' => 'Workflow.id',
            'element' => 'links',
            'class' => 'short',
            'url' => $baseurl . '/workflows/view/%s'
        ],
        [
            'name' => __('Last Update'),
            'class' => 'short',
            'sort' => 'Workflow.timestamp',
            'data_path' => 'Workflow.timestamp',
            'element' => 'datetime',
        ],
        [
            'name' => __('Debug enabled'),
            'sort' => 'Workflow.debug_enabled',
            'class' => 'short',
            'data_path' => 'Workflow.debug_enabled',
            'element' => 'checkbox_action',
            'onclick' => "enableWorkflowDebugMode(%s, %s)",
            'onclick_params_data_path' => ['Workflow.id', 'Workflow.debug_enabled'],
            'title' => __('Set the workflow in debug mode. Each nodes will send data to the provided debug URL')
        ],
        [
            'name' => __('Enabled'),
            'sort' => 'disabled',
            'class' => 'short',
            'data_path' => 'disabled',
            'element' => 'booleanOrNA',
            'boolean_reverse' => true,
            'colors' => true,
            'title' => __('Only enabled workflows will be executed when their trigger is called')
        ],
    ];

    $html_description = sprintf('<div>%s</div><div>%s</div>',
        __( 'Missing a trigger? Feel free to open a %s!',
            sprintf('<a href="%s">%s %s</a>', 'https://github.com/MISP/MISP/issues/new?assignees=&labels=feature+request%2Cneeds+triage&template=feature-request-form.yml&title=Feature+Request%3A+',
                sprintf('<i class="%s"></i>', $this->FontAwesome->getClass('github')),
                __('Github issue')
            )
        ),
        sprintf(
            '<a href="#workflow-info-modal" data-toggle="modal">%s %s</a>',
            sprintf('<i class="%s"></i>', $this->FontAwesome->getClass('info-circle')),
            __('Documentation and concepts')
        )
    );

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                [
                                    'url' => $baseurl . '/workflows/triggers',
                                    'text' => __('All'),
                                    'active' => empty($filters['scope']) && !isset($filters['enabled']) && empty($filters['blocking']),
                                ],
                            ],
                        ],
                        [
                            'type' => 'simple',
                            'children' => $scopesFilters,
                        ],
                        [
                            'type' => 'simple',
                            'children' => [
                                [
                                    'url' => $baseurl . '/workflows/triggers/blocking:1',
                                    'text' => __('Blocking'),
                                    'active' => !empty($filters['blocking']),
                                ],
                            ]
                        ],
                        [
                            'type' => 'simple',
                            'children' => [
                                [
                                    'url' => $baseurl . '/workflows/triggers/enabled:1',
                                    'text' => __('Enabled'),
                                    'active' => !empty($filters['enabled']),
                                ],
                                [
                                    'url' => $baseurl . '/workflows/triggers/enabled:0',
                                    'text' => __('Disabled'),
                                    'active' => isset($filters['enabled']) && empty($filters['enabled']),
                                ],
                            ]
                        ],
                    ]
                ],
                'fields' => $fields,
                'icon' => 'flag',
                'title' => __('Triggers'),
                'description' => __('List the available triggers that can be listened to by workflows.'),
                'html' => $html_description,
                'actions' => [
                    [
                        'title' => __('Enable'),
                        'icon' => 'play',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/toggleModule',
                        'url_params_data_paths' => ['id'],
                        'url_suffix' => '/1/1',
                        'postLinkConfirm' => __('Are you sure you want to enable this trigger?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && $options['datapath']['disabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'disabled' => 'disabled'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Disable'),
                        'icon' => 'stop',
                        'postLink' => true,
                        'url' => $baseurl . '/workflows/toggleModule',
                        'url_params_data_paths' => ['id'],
                        'url_suffix' => '/0/1',
                        'postLinkConfirm' => __('Are you sure you want to disable this trigger?'),
                        'complex_requirement' => array(
                            'function' => function ($row, $options) use ($isSiteAdmin) {
                                return $isSiteAdmin && !$options['datapath']['disabled'];
                            },
                            'options' => array(
                                'datapath' => array(
                                    'disabled' => 'disabled'
                                )
                            )
                        ),
                    ],
                    [
                        'title' => __('Edit associated workflows'),
                        'url' => $baseurl . '/workflows/editor',
                        'url_params_data_paths' => ['id'],
                        'icon' => 'code',
                        'dbclickAction' => true,
                    ],
                    [
                        'title' => __('View execution logs'),
                        'url' => $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow',
                        'url_named_params_data_paths' => ['model_id' => 'Workflow.id'],
                        'icon' => 'list-alt',
                        'complex_requirement' => [
                            'function' => function ($row, $options) {
                                return !empty($row['Workflow']);
                            },
                        ],
                    ],
                    [
                        'title' => __('View trigger details'),
                        'url' => $baseurl . '/workflows/moduleView',
                        'url_params_data_paths' => ['id'],
                        'icon' => 'eye',
                    ],
                ]
            ]
        ]
    ]);

    echo $this->element('/Workflows/infoModal');
?>
<script>
    $(document).ready(function() {
        $('[data-toggle="tooltip"]').tooltip();
    });
</script>