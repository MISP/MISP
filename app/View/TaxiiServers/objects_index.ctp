<?php
    $next_url = '';
    if ($more) {
        $next_url = $baseurl . '/taxiiServers/objectsIndex/' . h($id) . '/' . h($collection_id) . '/' . h($next);
    }
    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'skip_pagination' => 1,
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                'data' => [
                                    'type' => 'simple',
                                    'text' => __('Next page'),
                                    'class' => 'btn btn-primary',
                                    'url' => $next_url,
                                    'requirement' => $more
                                ]
                            ]
                        ],
                    ]
                ],
                'fields' => [
                    [
                        'name' => __('Id'),
                        'data_path' => 'id'
                    ],
                    [
                        'name' => __('Type'),
                        'data_path' => 'type'
                    ],
                    [
                        'name' => __('Created'),
                        'data_path' => 'created'
                    ],
                    [
                        'name' => __('Modified'),
                        'data_path' => 'modified'
                    ],
                    [
                        'name' => __('Labels'),
                        'element' => 'list',
                        'data_path' => 'labels'
                    ],
                    [
                        'name' => __('STIX version'),
                        'data_path' => 'spec_version'
                    ]
                ],
                'title' => empty($ajax) ? __('Objects found in Collection %s on TaxiiServer #%s', h($collection_id), h($id)) : false,
                'description' => false,
                'actions' => [
                    [
                        'onclick' => 'openGenericModal(\'' . h($baseurl) . '/taxiiServers/objectView/' . h($id) . '/' . h($collection_id) . '/%s\');',
                        'onclick_replace' => ['id'],
                        'title' => __('View raw STIX object'),
                        'icon' => 'eye'
                    ]
                ]
            ]
        ]
    ]);

?>
