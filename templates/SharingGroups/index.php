<div class="sharingGroups<?php if (!$ajax) echo ' index' ?>">
<?= $this->element(
    '/genericElements/IndexTable/index_table',
    [
    'data' => [
        'title' => __('Sharing Groups'),
        'data' => $sharingGroups,
        'top_bar' => $ajax ? [] : [
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        [
                            'text' => __('Add'),
                            'fa-icon' => 'plus',
                            'url' => '/sharingGroups/add',
                            'requirement' => $this->Acl->checkAccess('sharingGroups', 'add'),
                        ]
                    ]
                ],
                [
                    'type' => 'simple',
                    'children' => [
                        [
                            'url' => '/sharingGroups/index',
                            'text' => __('Active Sharing Groups'),
                            'active' => !$passive,
                        ],
                        [
                            'url' => '/sharingGroups/index/true',
                            'text' => __('Passive Sharing Groups'),
                            'active' => $passive,
                        ]
                    ]
                ],
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'searchKey' => 'value',
                    'cancel' => [
                        'fa-icon' => 'times',
                        'title' => __('Remove filters'),
                        'onClick' => 'cancelSearch',
                    ]
                ]
            ]
        ],
        'fields' => [
            [
                'name' => __('ID'),
                'sort' => 'id',
                'class' => 'short',
                'data_path' => 'id',
                'url' => '/sharingGroups/view/{{id}}',
                'url_vars' => ['id' => 'id']
            ],
            [
                'name' => __('UUID'),
                'data_path' => 'uuid',
                'sort' => 'uuid',
                'class' => 'short quickSelect',
            ],
            [
                'name' => __('Name'),
                'data_path' => 'name',
                'sort' => 'name',
                'class' => 'short',
            ],
            [
                'name' => __('Creator'),
                'sort' => 'Organisation.name',
                'element' => 'org',
                'data_path' => 'Organisation',
                'class' => 'short',
            ],
            [
                'name' => __('Description'),
                'data_path' => 'description',
            ],
            [
                'name' => __('Org count'),
                'class' => 'short',
                'sort' => 'org_count',
                'data_path' => 'org_count',
            ],
            [
                'name' => __('Releasable to'),
                'element' => 'custom',
                'function' => function (array $sharingGroup) {
                    $combined = __("Organisations:");
                    if (empty($sharingGroup['SharingGroupOrg'])) {
                        $combined .= "<br>N/A";
                    } else {
                        foreach ($sharingGroup['SharingGroupOrg'] as $sge) {
                            if (!empty($sge['Organisation'])) {
                                $combined .= "<br><a href='/organisation/view/" . h($sge['Organisation']['id']) . "'>" . h($sge['Organisation']['name']) . "</a>";
                                if ($sge['extend']) {
                                    $combined .= ' (can extend)';
                                }
                            }
                        }
                    }
                    $combined .= '<hr style="margin:5px 0;"><br>Instances:';
                    if (empty($sharingGroup['SharingGroupServer'])) {
                        $combined .= "<br>N/A";
                    } else {
                        foreach ($sharingGroup['SharingGroupServer'] as $sgs) {
                            if ($sgs['server_id'] != 0) {
                                $combined .= "<br><a href='/server/view/" . h($sgs['Server']['id']) . "'>" . h($sgs['Server']['name']) . "</a>";
                            } else {
                                $combined .= "<br>This instance";
                            }
                            if ($sgs['all_orgs']) {
                                $combined .= ' (all organisations)';
                            } else {
                                $combined .= ' (as defined above)';
                            }
                        }
                    } ?>
                    <span data-toggle="popover" data-trigger="hover" title="<?= __('Distribution List') ?>" data-content="<?= h($combined) ?>">
                        <?= empty($sharingGroup['releasability']) ?
                            '<span style="color: gray">' . __('Not defined') . '</span>' :
                            h($sharingGroup['releasability'])
                        ?>
                    </span>
                    <?php
                },
            ]
        ],
        'actions' => [
            [
                'url' => '/sharingGroups/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye',
                'title' => __('View Sharing Group'),
            ],
            [
                'url' => '/sharingGroups/edit',
                'url_params_data_paths' => ['id'],
                'icon' => 'edit',
                'complex_requirement' => [
                    'function' => function (array $sharingGroup) {
                        return $sharingGroup['editable'];
                    }
                ],
                'title' => __('Edit Sharing Group'),
            ],
            [
                'url' => '/sharingGroups/delete',
                'url_params_data_paths' => ['id'],
                'postLinkConfirm' => __('Are you sure you want to delete the sharing group?'),
                'icon' => 'trash',
                'complex_requirement' => [
                    'function' => function (array $sharingGroup) {
                        return $sharingGroup['deletable'];
                    }
                ],
                'title' => __('Delete Sharing Group'),
            ],
        ]
    ]
    ]
);
?>
</div>
<script type="text/javascript">
    $(function(){
        popoverStartup();
    });
</script>
<?php
// TODO: [3.x-MIGRATION]
// if (!$ajax) {
//     echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'indexSG'));
// }
