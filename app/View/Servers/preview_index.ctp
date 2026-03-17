<?php
    echo '<div class="events index">';
    $serverName = $server['Server']['name'] ? '"' . $server['Server']['name'] . '" (' . $server['Server']['url'] . ')' : '"' . $server['Server']['url'] . '"';
    $eventViewURL = $baseurl . '/servers/previewEvent/' . h($id);
    $eventPullURL = $baseurl . '/servers/pull/' . h($id);
    echo '<h4 class="visibleDL notPublished" >' . __('You are currently viewing the event index of the remote instance %s', h($serverName)) . '</h4>';
    $filterParamsString = [];
        foreach ($passedArgsArray as $k => $v) {
            $filterParamsString[] = sprintf(
                '%s: %s',
                h(ucfirst($k)),
                h($v)
            );
        }
        $filterParamsString = implode(' & ', $filterParamsString);
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'title' => '',
            'data' => $events,
            'paginatorOptions' => [
                'url' => $server['Server']['id'],
            ],
            'top_bar' => [
                'children' => [
                    [
                        'children' => [
                            [
                                'id' => 'create-button',
                                'title' => __('Modify filters'),
                                'fa-icon' => 'search',
                                'onClick' => 'getPopup',
                                'onClickParams' => array(h($urlparams), 'servers', 'filterEventIndex/' . h($server['Server']['id']))
                            ]
                        ]
                    ],
                    [
                        'children' => [
                            [
                                'requirement' => !empty($passedArgsArray),
                                'html' => sprintf(
                                    '<span class="bold">%s</span>: %s',
                                    __('Filters'),
                                    $filterParamsString
                                )
                            ],
                            [
                                'requirement' => !empty($passedArgsArray),
                                'url' => $baseurl . '/servers/previewIndex/' . h($server['Server']['id']),
                                'title' => __('Remove filters'),
                                'fa-icon' => 'times'
                            ]
                        ]
                    ],
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'searchall'
                    ]
                ]
            ],
            'fields' => [
                [
                    'name' => __('Published'),
                    'element' => 'boolean',
                    'sort' => 'Event.published',
                    'class' => 'short',
                    'data_path' => 'Event.published',
                ],
                [
                    'name' => __('Org'),
                    'sort' => 'Orgc.name',
                    'class' => 'short',
                    'data_path' => 'Event.Orgc.name',
                ],
                [
                    'name' => __('Owner org'),
                    'sort' => 'Org.name',
                    'class' => 'short',
                    'data_path' => 'Event.Org.name',
                ],
                [
                    'name' => __('ID'),
                    'class' => 'dblclickElement',
                    'element' => 'count',
                    'sort' => 'Event.id',
                    'data_path' => 'Event.id',
                    'url' => $eventViewURL . '/%s',
                    'url_params_data_path' => [
                        'Event.id'
                    ],
                ],
                [
                    'name' => __('Tags'),
                    'requirement' => Configure::read('MISP.tagging'),
                    'class' => 'short',
                    'element' => 'tags',
                    'scope' => 'attribute',
                    'skip_modifications' => true,
                    'data_path' => 'Event.EventTag',
                ],
                [
                    'name' => __('#Attr.'),
                    'sort' => 'Event.attribute_count',
                    'class' => 'short',
                    'style' => 'font-weight: bold;',
                    'data_path' => 'Event.attribute_count',
                    'link' => [
                        'url' => $eventViewURL . '%s',
                        'param_path' => 'Event.id',
                    ]
                ],
                [
                    'name' => __('Date'),
                    'sort' => 'Event.date',
                    'class' => 'short',
                    'data_path' => 'Event.date',
                ],
                [
                    'name' => __('Threat Level'),
                    'sort' => 'Event.threat_level_id',
                    'class' => 'short',
                    'data_path' => 'Event.threat_level_id',
                    'element' => 'threat_levels',
                ],
                [
                    'name' => __('Analysis'),
                    'sort' => 'Event.analysis',
                    'class' => 'short',
                    'data_path' => 'Event.analysis',
                    'element' => 'analysis',
                ],
                [
                    'name' => __('Info'),
                    'sort' => 'Event.info',
                    'data_path' => 'Event.info',
                ],
                [
                    'name' => __('Distribution'),
                    'sort' => 'Event.distribution',
                    'class' => 'short',
                    'data_path' => 'Event.distribution',
                    'element' => 'distribution_levels',
                ],
            ],
            'actions' => [
                [
                    'url' => $eventPullURL,
                    'url_params_data_paths' => [
                        'Event.id'
                    ],
                    'icon' => 'arrow-circle-down',
                    'title' => __('Fetch the event'),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to fetch and save this event on your instance?'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return !empty($row['Event']['published']);
                        }
                    ]
                ],
                [
                    'url' => $eventPullURL,
                    'url_params_data_paths' => [
                        'Event.id'
                    ],
                    'icon' => 'arrow-circle-down',
                    'title' => __('Fetch the event'),
                    'color' => 'grey',
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to fetch and save this event on your instance?  Warning: This event is not published on the remote end.'),
                    'complex_requirement' => [
                        'function' => function ($row) {
                            return empty($row['Event']['published']);
                        }
                    ]
                ],
                [
                    'url' => $eventViewURL,
                    'url_params_data_paths' => [
                        'Event.id'
                    ],
                    'icon' => 'eye',
                    'title' => __('View')
                ]
            ]
        ]
    ]);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'previewIndex', 'id' => $id));
?>

<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('<?php echo '/' . h($server['Server']['id']);?>');
        });
    });
</script>
