<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $list,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [
                            [
                                'active' => !empty($exclude_statistics),
                                'url' => $baseurl . '/tags/index/exclude_statistics:1',
                                'text' => __('Simple'),
                            ],
                            [
                                'active' => empty($exclude_statistics),
                                'url' => $baseurl . '/tags/index',
                                'text' => __('Advanced'),
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
                    'name' => __('ID'),
                    'sort' => 'Tag.id',
                    'class' => 'short',
                    'data_path' => 'Tag.id',
                ],
                [
                    'name' => __('Exportable'),
                    'element' => 'boolean',
                    'sort' => 'Tag.exportable',
                    'class' => 'short',
                    'data_path' => 'Tag.exportable',
                ],
                [
                    'name' => __('Hidden'),
                    'sort' => 'Tag.hidden',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Tag.hidden',
                ],
                [
                    'name' => __('Name'),
                    'sort' => 'Tag.name',
                    'class' => 'short',
                    'element' => 'tags',
                    'data_path' => 'Tag',
                    'scope' => 'tags',
                    'hide_global_scope' => true
                ],
                [
                    'name' => __('Restricted to org'),
                    'sort' => 'Tag.org_id',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Tag.org_id'
                ],
                [
                    'name' => __('Restricted to user'),
                    'sort' => 'Tag.user_id',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'Tag.user_id'
                ],
                [
                    'name' => __('Taxonomy'),
                    'class' => 'short',
                    'element' => 'links',
                    'data_path' => 'Tag.Taxonomy.namespace',
                    'url' => '/taxonomies/view',
                    'url_params_data_paths' => ['Tag.Taxonomy.id']
                ],
                [
                    'name' => __('Tagged events'),
                    'sort' => 'Tag.count',
                    'class' => 'short',
                    'element' => 'count',
                    'data_path' => 'Tag.count',
                    'requirement' => empty($exclude_statistics)
                ],
                [
                    'name' => __('Tagged attributes'),
                    'sort' => 'Tag.attribute_count',
                    'class' => 'short',
                    'element' => 'count',
                    'data_path' => 'Tag.attribute_count',
                    'url' => '/attributes/search/tags:%d',
                    'url_params_data_path' => ['Tag.id'],
                    'requirement' => empty($exclude_statistics)
                ],
                [
                    'name' => __('Activity'),
                    'class' => 'short',
                    'element' => 'sparkline',
                    'data_path' => 'Tag.id',
                    'csv_data_path' => 'Tag.csv',
                    'requirement' => empty($exclude_statistics)
                ],
                [
                    'name' => __('Favourite'),
                    'data_path' => 'Tag.favourite',
                    'element' => 'checkbox_action',
                    'onclick' => "toggleSetting(event, 'favourite_tag', %s)",
                    'onclick_params_data_path' => ['Tag.id'],
                    'checkbox_name' => 'GenericCheckbox'
                ]
            ],
            'title' => __('Tags'),
            'actions' => [
                [
                    'url' => $baseurl . '/tags/viewGraph',
                    'url_params_data_paths' => [
                        'Tag.id'
                    ],
                    'icon' => 'share-alt',
                    'title' => __('View graph')
                ],
                [
                    'url' => $baseurl . '/tags/edit',
                    'url_params_data_paths' => [
                        'Tag.id'
                    ],
                    'icon' => 'edit',
                    'title' => __('Edit'),
                    'requirement' => $isSiteAdmin,
                ],
                [
                    'url' => $baseurl . '/tags/delete',
                    'url_params_data_paths' => [
                        'Tag.id'
                    ],
                    'postLink' => '',
                    'postLinkConfirm' => __('Are you sure you want to delete the Tag?'),
                    'icon' => 'trash',
                    'title' => __('Delete tag'),
                    'requirement' => $isSiteAdmin,
                ],
            ]
        ]
    ]);
    echo sprintf(
        '<div id="hiddenFormDiv">%s%s%s</div>',
        $this->Form->create('FavouriteTag', array('url' => $baseurl . '/favourite_tags/toggle')),
        $this->Form->input('data', array('label' => false, 'style' => 'display:none;')),
        $this->Form->end()
    );
    echo '</div>';
    echo $this->element(
        '/genericElements/SideMenu/side_menu', [
            'menuList' => 'tags',
            'menuItem' => $favouritesOnly ? 'indexfav' : 'index'
        ]
    );
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
