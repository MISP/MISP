<?php
    echo '<div class="objectTemplates index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'title' => __('Object Template index'),
            'data' => $list,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'simple',
                        'children' => [
                            [
                                'active' => empty($all),
                                'url' => $baseurl . '/objectTemplates/index',
                                'text' => __('Enabled'),
                            ],
                            [
                                'active' => !empty($all),
                                'url' => $baseurl . '/objectTemplates/index/all',
                                'text' => __('All'),
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
                    'name' => __('Active'),
                    'data_path' => 'ObjectTemplate.active',
                    'sort' => 'ObjectTemplate.active',
                    'class' => 'short',
                    'element' => 'checkbox_action',
                    'onclick' => "toggleSetting(event, 'activate_object_template', %s)",
                    'onclick_params_data_path' => ['ObjectTemplate.id'],
                    'checkbox_name' => 'GenericCheckbox'
                ],
                [
                    'name' => __('ID'),
                    'sort' => 'ObjectTemplate.id',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplate.id',
                ],
                [
                    'name' => __('Name'),
                    'sort' => 'ObjectTemplate.name',
                    'element' => 'object_template_name',
                    'class' => 'shortish',
                    'data_path' => 'ObjectTemplate'
                ],
                [
                    'name' => __('UUID'),
                    'sort' => 'ObjectTemplate.uuid',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplate.uuid',
                ],
                [
                    'name' => __('Organisation'),
                    'sort' => 'Organisation.name',
                    'element' => 'org',
                    'class' => 'short',
                    'data_path' => 'Organisation',
                ],
                [
                    'name' => __('Version'),
                    'sort' => 'ObjectTemplate.version',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplate.version',
                ],
                [
                    'name' => __('Meta-category'),
                    'sort' => 'ObjectTemplate.meta-category',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplate.meta-category',
                ],
                [
                    'name' => __('Description'),
                    'sort' => 'ObjectTemplate.descripition',
                    'class' => 'long',
                    'data_path' => 'ObjectTemplate.description',
                ],
                [
                    'name' => __('Requirements'),
                    'class' => 'short',
                    'element' => 'object_template_requirements',
                    'data_path' => 'ObjectTemplate.requirements'
                ]
            ],
            'actions' => [
                [
                    'url' => $baseurl . '/objectTemplates/view',
                    'url_params_data_paths' => [
                        'ObjectTemplate.id'
                    ],
                    'icon' => 'eye',
                    'title' => __('View')
                ],
                [
                    'url' => $baseurl . '/objectTemplates/update',
                    'url_params_data_paths' => [
                        'ObjectTemplate.id'
                    ],
                    'postLink' => '',
                    'postLinkConfirm' => __('Are you sure you want to force an update for this template ?'),
                    'icon' => 'sync',
                    'title' => __('Force update'),
                    'requirement' => $isSiteAdmin,
                ],
                [
                    'url' => $baseurl . '/objectTemplates/delete',
                    'url_params_data_paths' => [
                        'ObjectTemplate.id'
                    ],
                    'postLink' => '',
                    'postLinkConfirm' => __('Are you sure you want to delete this template ?'),
                    'icon' => 'trash',
                    'title' => __('Delete'),
                    'requirement' => $isSiteAdmin,
                ]
            ]
        ]
    ]);
    echo sprintf(
        '<div id="hiddenFormDiv">%s%s%s</div>',
        $this->Form->create('ObjectTemplate', ['url' => $baseurl . '/objectTemplates/activate']),
        $this->Form->input('data', ['label' => false, 'style' => 'display:none;']),
        $this->Form->end()
    );
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'objectTemplates', 'menuItem' => 'index'));
?>
<script type="text/javascript">
    $(document).ready(function(){
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
