<?php

use App\Model\Entity\SharingGroup;
?>
<?= $this->element(
    '/genericElements/IndexTable/index_table',
    [
        'data' => [
            'title' => __('Sharing Groups'),
            'data' => $data,
            'top_bar' => [
                'children' => [
                    [
                        'type' => 'multi_select_actions',
                        'force-dropdown' => true,
                        'children' => [
                            [
                                'text' => __('Delete sharing groups'),
                                'icon' => 'trash',
                                'variant' => 'danger',
                                'outline' => true,
                                'onclick' => 'deleteSharingGroups',
                            ],
                            ['is-header' => true, 'text' => __('Toggle selected sharing groups'), 'icon' => 'user-times',],
                            [
                                'text' => __('Disable sharing groups'),
                                'variant' => 'warning',
                                'outline' => true,
                                'onclick' => 'disableSharingGroups',
                                'class' => 'text-end',
                            ],
                            [
                                'text' => __('Enable sharing groups'),
                                'variant' => 'success',
                                'outline' => true,
                                'onclick' => 'enableSharingGroups',
                                'class' => 'text-end',
                            ],
                        ],
                        'data' => [
                            'id' => [
                                'value_path' => 'id'
                            ]
                        ]
                    ],
                    [
                        'type' => 'simple',
                        'children' => [
                            'data' => [
                                'type' => 'simple',
                                'text' => __('Add sharing'),
                                'popover_url' => '/sharing-groups/add',
                                'button' => [
                                    'icon' => 'plus',
                                ]
                            ]
                        ]
                    ],
                    [
                        'type' => 'context_filters',
                    ],
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value',
                        'allowFilering' => true
                    ],
                    [
                        'type' => 'table_action',
                        'table_setting_id' => 'sharinggroup_index',
                    ]
                ]
            ],
            'fields' => [
                [
                    'name' => __('ID'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'id',
                    'url' => '/sharing-groups/view/{{id}}',
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
                    'function' => function (SharingGroup $sharingGroup) {
                        $combined = __("Organisations:");
                        if (empty($sharingGroup['SharingGroupOrg'])) {
                            $combined .= "<br>N/A";
                        } else {
                            foreach ($sharingGroup['SharingGroupOrg'] as $sge) {
                                if (!empty($sge['Organisation'])) {
                                    $combined .= "<br><a href='/organisation/view/" . h($sge['Organisation']['id']) . "'>" . h($sge['Organisation']['name']) . "</a>";
                                    if ($sge['extend']) {
                                        $combined .= __(' (can extend)');
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
                                    $combined .= "<br>" . __("This instance");
                                }
                                if ($sgs['all_orgs']) {
                                    $combined .= __(' (all organisations)');
                                } else {
                                    $combined .= __(' (as defined above)');
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
                ],
                [
                    'name' => __('Roaming'),
                    'sort' => 'roaming',
                    'data_path' => 'roaming',
                    'element' => 'boolean',
                    'colors' => [true => 'success', false => 'muted'],
                ],
                [
                    'name' => __('Active'),
                    'sort' => 'active',
                    'data_path' => 'active',
                    'element' => 'boolean',
                    'colors' => [true => 'muted', false => 'danger'],
                ],
            ],
            'actions' => [
                [
                    'url' => '/sharing-groups/view',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'eye',
                    'title' => __('View Sharing Group'),
                ],
                [
                    'url' => '/sharing-groups/edit',
                    'url_params_data_paths' => ['id'],
                    'icon' => 'edit',
                    'complex_requirement' => [
                        'function' => function (SharingGroup $sharingGroup) {
                            return $sharingGroup['editable'];
                        }
                    ],
                    'title' => __('Edit Sharing Group'),
                ],
                [
                    'url' => '/sharing-groups/delete',
                    'url_params_data_paths' => ['id'],
                    'postLinkConfirm' => __('Are you sure you want to delete the sharing group?'),
                    'icon' => 'trash',
                    'complex_requirement' => [
                        'function' => function (SharingGroup $sharingGroup) {
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

<script>
    function enableSharingGroups(idList, selectedData, $table) {
        return massToggle('active', true, idList, selectedData, $table)
    }

    function disableSharingGroups(idList, selectedData, $table) {
        return massToggle('active', false, idList, selectedData, $table)
    }

    function deleteSharingGroups(idList, selectedData, $table) {
        const url = `<?= $baseurl ?>/sharing-groups/delete?ids=${JSON.stringify(idList)}`
        const reloadUrl = '<?= $baseurl ?>/sharing-groups/index'
        UI.submissionModalForIndex(url, reloadUrl, $table)
    }


    function massToggle(field, enabled, idList, selectedData, $table) {
        const url = `<?= $baseurl ?>/sharing-groups/massToggleField?${field}=${enabled ? 1 : 0}&ids=${JSON.stringify(idList)}`
        const reloadUrl = '<?= $baseurl ?>/sharing-groups/index'
        UI.submissionModalForIndex(url, reloadUrl, $table)
    }
</script>