<?php
    $fields = [
        [
            'name' => __('Id'),
            'sort' => 'id',
            'data_path' => 'id'
        ],
        [
            'name' => __('Status'),
            'sort' => 'exists_locally',
            'element' => 'remote_status',
            'data_path' => ''
        ],
        [
            'name' => __('UUID'),
            'sort' => 'uuid',
            'data_path' => 'uuid'
        ],
        [
            'name' => __('Name'),
            'sort' => 'name',
            'data_path' => 'name'
        ],
        [
            'name' => __('Sector'),
            'sort' => 'sector',
            'data_path' => 'sector'
        ],
        [
            'name' => __('Nationality'),
            'sort' => 'nationality',
            'data_path' => 'nationality'
        ]
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'preserve_url_params' => [$cerebrate['Cerebrate']['id']],
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => empty($ajax) ? __(
                        'Organisations list via Cerebrate %s (%s)',
                        h($cerebrate['Cerebrate']['id']),
                        h($cerebrate['Cerebrate']['name'])
                    ) : false,
                'description' => empty($ajax) ? __('Preview of the organisations known to the remote Cerebrate instance.') : false,
                'actions' => [
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/cerebrates/download_org/%s/[onclick_params_data_path]\');',
                            $baseurl,
                            h($cerebrate['Cerebrate']['id'])
                        ),
                        'onclick_params_data_path' => 'id',
                        'icon' => 'download',
                        'title' => __('Fetch organisation object')
                    ]
                ],
                'paginatorOptions' => [
                    'url' => [$cerebrate['Cerebrate']['id']]
                ],
                'persistUrlParams' => [0, 'quickFilter']
            ],
            'containerId' => 'preview_orgs_container'
        ]
    ]);
?>
<script type="text/javascript">
    var passedArgsArray = <?= json_encode([h($cerebrate['Cerebrate']['id'])]) ?>;
</script>
