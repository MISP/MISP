<?php
$searchScopes = [
    'searcheventinfo' => __('Event info'),
    'searchall' => __('All fields'),
    'searcheventid' => __('ID / UUID'),
    'searchtags' => __('Tag'),
];
$searchKey = 'searcheventinfo';

$filterParamsString = [];
foreach ($passedArgsArray as $k => $v) {
    if (isset($searchScopes["search$k"])) {
        $searchKey = "search$k";
    }

    $filterParamsString[] = sprintf(
        '%s: %s',
        h(ucfirst($k)),
        h(is_array($v) ? http_build_query($v) : $v)
    );
}
$filterParamsString = implode(' & ', $filterParamsString);

$columnsDescription = [
    'owner_org' => __('Owner org'),
    'attribute_count' => __('Attribute count'),
    'creator_user' => __('Creator user'),
    'tags' => __('Tags'),
    'clusters' => __('Clusters'),
    'correlations' => __('Correlations'),
    'sightings' => __('Sightings'),
    'proposals' => __('Proposals'),
    'discussion' => __('Posts'),
    'report_count' => __('Report count'),
    'timestamp' => __('Last modified at'),
    'publish_timestamp' => __('Published at'),
    'is_extension' => __('Is extension'),
    'highlights' => __('Highlights'),
];

$columnsMenu = [];
foreach ($possibleColumns as $possibleColumn) {
    $html = in_array($possibleColumn, $columns, true) ? '<i class="fa fa-check"></i> ' : '<i class="fa fa-check" style="visibility: hidden"></i> ';
    $html .= $columnsDescription[$possibleColumn];
    $columnsMenu[] = [
        'html' => $html,
        'onClick' => 'eventIndexColumnsToggle',
        'onClickParams' => [$possibleColumn],
    ];
}
$fields = [
    [
        'element' => 'selector',
        'class' => 'short',
        'data' => [
            'id' => [
                'value_path' => 'Event.id'
            ]
        ]
    ],
    [
        'name' => __('Id'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id',
        'element' => 'eventid'
    ],
    [
        'icon' => 'upload',
        'sort' => 'Event.published',
        'data_path' => 'Event.published'
    ],
    [
        'name' => __('Orgc/Org'),
        'sort' => 'Orgc',
        'element' => 'orgs',
        'requirement' => Configure::read('MISP.showorg')
    ],
    [
        'name' => __('Clusters'),
        'element' => 'galaxy_clusters',
        'sort' => 'Clusters',
        'data_path' => 'GalaxyCluster'
    ],
    [
        'name' => __('Tags'),
        'class' => 'short',
        'data_path' => 'EventTag.{n}.Tag',
        'element' => 'tags',
        'elementParams' => array(
            'searchScope' => 'taxonomy',
        ),
        'scope' => 'event',
        'skip_modifications' => true,
        'addButtonOnly' => false,
        'id_data_path' => 'Event.id',
    ],
    [
        'name' => __('Info'),
        'data_path' => 'Event.info'
    ],
    [
        'name' => __('#Attr.'),
        'title' => __('Attribute'),
        'sort' => 'Event.attribute_count',
        'data_path' => 'Event.attribute_count'
    ],
    [
        'name' => __('#Corr.'),
        'header_title' => __('Correlation count'),
        'sort' => 'Event.correlation_count',
        'data_path' => 'Event.correlation_count'
    ],
    [
        'name' => __('#Rep.'),
        'header_title' => __('Report count'),
        'sort' => 'Event.report_count',
        'data_path' => 'Event.report_count'
    ],
    [
        'name' => __('#Sight.'),
        'header_title' => __('Sighting count'),
        'sort' => 'Event.sightings_count',
        'data_path' => 'Event.sightings_count'
    ],
    [
        'name' => __('#Prop.'),
        'header_title' => __('Proposal count'),
        'sort' => 'Event.proposals_count',
        'data_path' => 'Event.proposals_count'
    ],
    [
        'name' => __('Creator user'),
        'sort' => 'User.email',
        'data_path' => 'User.email'
    ],
    [
        'name' => __('Modified'),
        'element' => 'datetime',
        'sort' => 'Event.timestamp',
        'data_path' => 'Event.timestamp'
    ],
    [
        'name' => __('Distribution'),
        'element' => 'distribution_levels',
        'data_path' => 'Event.distribution'
    ]
    
];

echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $events,
        'top_bar' => [
            'pull' => 'right',
            'children' => [
                [
                    'children' => [
                        [
                            'id' => 'create-button',
                            'title' => __('Modify filters'),
                            'button' => [
                                'icon' => 'search'
                            ],
                            'onClick' => 'getPopup',
                            'onClickParams' => array(h($urlparams), 'events', 'filterEventIndex')
                        ]
                    ]
                ],
                [
                    'children' => [
                        [
                            'id' => 'multi-delete-button',
                            'title' => __('Delete selected events'),
                            'button' => [
                                'icon' => 'trash'
                            ],
                            'class' => 'hidden mass-delete',
                            'onClick' => 'multiSelectDeleteEvents'
                        ],
                        [
                            'id' => 'multi-export-button',
                            'title' => __('Export selected events'),
                            'button' => [
                                'icon' => 'file-export'
                            ],
                            'class' => 'hidden mass-export',
                            'onClick' => 'multiSelectExportEvents'
                        ]
                    ],
                ],
                [
                    'children' => [
                        [
                            'requirement' => count($passedArgsArray) > 0,
                            'html' => sprintf(
                                '<span class="bold">%s</span>: %s',
                                __('Filters'),
                                $filterParamsString
                            )
                        ],
                        [
                            'requirement' => count($passedArgsArray) > 0,
                            'url' => $baseurl . '/events/index',
                            'title' => __('Remove filters'),
                            'fa-icon' => 'times'
                        ]
                    ]
                ],
                [
                    'children' => [
                        [
                            'title' => __('My events only'),
                            'text' => __('My Events'),
                            'data' => [
                                'searchemail' => h($me['email'])
                            ],
                            'class' => 'searchFilterButton',
                            'active' => isset($passedArgsArray['email']) && $passedArgsArray['email'] === $me['email']
                        ],
                        [
                            'title' => __('My organisation\'s events only'),
                            'text' => __('Org Events'),
                            'data' => array(
                                'searchorg' => h($me['org_id'])
                            ),
                            'class' => 'searchFilterButton',
                            'active' => isset($passedArgsArray['org']) && $passedArgsArray['org'] === $me['org_id']
                        ]
                    ]
                ],
                [
                    'children' => [
                        [
                            'id' => 'simple_filter',
                            'type' => 'group',
                            'class' => 'last',
                            'title' => __('Choose columns to show'),
                            'fa-icon' => 'columns',
                            'children' => $columnsMenu,
                        ],
                    ],
                ],
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchScopes' => $searchScopes,
                    'searchKey' => $searchKey,
                ]
            ]
        ],
        'fields' => $fields,
        'title' => empty($ajax) ? __('Events') : false,
        'description' => false,
        'actions' => [
            [
                'open_modal' => '/events/publish/[onclick_params_data_path]',
                'modal_params_data_path' => 'Event.id',
                'title' => __('Publish event'),
                'icon' => 'upload',
            ],
            [
                'open_modal' => '/events/edit/[onclick_params_data_path]',
                'modal_params_data_path' => 'Event.id',
                'title' => __('Edit event'),
                'icon' => 'edit',
            ],
            [
                'open_modal' => '/events/delete/[onclick_params_data_path]',
                'modal_params_data_path' => 'Event.id',
                'title' => __('Delete event'),
                'icon' => 'trash',
            ],
            [
                'url' => '/events/view',
                'url_params_data_paths' => ['Event.id'],
                'title' => __('View event'),
                'icon' => 'eye',
            ],
        ]
    ]
]);

?>
<script>
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('.searchFilterButton').click(function() {
            runIndexFilter(this);
        });
        $('#quickFilterScopeSelector').change(function() {
            $('#quickFilterField').data('searchkey', this.value)
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['vis', 'distribution-graph'],
    'js' => ['vis', 'jquery-ui.min', 'network-distribution-graph'],
]);
if (!$ajax) {
    //echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'index'));
}
