<?php
    $fields = [
        [
            'name' => __('ID'),
            'sort' => 'id',
            'data_path' => 'id',
        ],
        [
            'name' => __('Name'),
            'sort' => 'name',
            'data_path' => 'name',
            'element' => 'custom',
            'function' => function (array $relationship) {
                return sprintf('<div style="white-space: nowrap; font-size: 1.15em;"><code>%s</code></div>', 
                    h($relationship['name']),
                );
            }
        ],
        [
            'name' => __('Description'),
            'sort' => 'description',
            'data_path' => 'description',
        ],
        [
            'name' => __('Format'),
            'sort' => 'format',
            'data_path' => 'format',
            'element' => 'custom',
            'function' => function (array $relationship) {
                return implode(', ', array_map('h', $relationship['format']));
            }
        ],
        [

            'name' => __('Version'),
            'sort' => 'version',
            'data_path' => 'version',
        ],
        [
            'name' => __('Highlighted'),
            'element' => 'toggle',
            'url' => $baseurl . '/object_relationships/toggleHighlighted',
            'url_params_data_paths' => array(
                'name'
            ),
            'sort' => 'highlighted',
            'class' => 'short',
            'data_path' => 'highlighted',
            'disabled' => !$isSiteAdmin,
        ],
        [

            'name' => __('Usage'),
            'sort' => 'usage_all',
            'data_path' => 'usage',
            'element' => 'custom',
            'function' => function (array $relationship) {
                if (empty($relationship['usage'])) {
                    $relationship['usage']['object_reference'] = 0;
                    $relationship['usage']['tag_relationship'] = 0;
                    $relationship['usage']['analyst_relationship'] = 0;
                }
                return sprintf(
                '<div style="white-space: nowrap;">%s%s%s%s%s%s</div>',
                    sprintf('<span class="%s" style="margin-right: 0.25em;" title="%s"></span>', $this->FontAwesome->getClass('project-diagram'), __('# of Object Reference using this relationship')),
                    h($relationship['usage']['object_reference'] ?? 0),
                    sprintf('<span class="%s" style="margin-right: 0.25em; margin-left: 0.5em;" title="%s"></span>', $this->FontAwesome->getClass('tag'), __('# of Tag Relationship using this relationship')),
                    h($relationship['usage']['tag_relationship'] ?? 0),
                    sprintf('<span class="%s" style="margin-right: 0.25em; margin-left: 0.5em;" title="%s"></span>', $this->FontAwesome->getClass('arrow-up'), __('# of Analyst Relationship using this relationship')),
                    h($relationship['usage']['analyst_relationship'] ?? 0),
                );
            }
        ],
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                [
                                    'text' => __('Add'),
                                    'fa-icon' => 'plus',
                                    'url' => $baseurl . '/ObjectRelationships/add',
                                    'requirement' => $isSiteAdmin,
                                ]
                            ]
                        ],
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => empty($ajax) ? __('Object Relationship index') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/ObjectRelationships/edit',
                        'url_params_data_paths' => ['id'],
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/ObjectRelationships/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
