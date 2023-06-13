<div class="sharing_groups<?php if (!$ajax) echo ' index' ?>">
<?= $this->element('/genericElements/IndexTable/index_table', array(
    'data' => array(
        'title' => __('Sharing Groups'),
        'data' => $sharingGroups,
        'top_bar' => $ajax ? [] : array(
            'children' => array(
                array(
                    'type' => 'simple',
                    'children' => array(
                        array(
                            'text' => __('Add'),
                            'fa-icon' => 'plus',
                            'url' => $baseurl . '/sharing_groups/add',
                            'requirement' => $this->Acl->checkAccess('sharing_groups', 'add'),
                        )
                    )
                ),
                array(
                    'type' => 'simple',
                    'children' => array(
                        array(
                            'url' => $baseurl . '/sharing_groups/index',
                            'text' => __('Active Sharing Groups'),
                            'active' => !$passive,
                        ),
                        array(
                            'url' => $baseurl . '/sharing_groups/index/true',
                            'text' => __('Passive Sharing Groups'),
                            'active' => $passive,
                        )
                    )
                ),
                array(
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'searchKey' => 'value',
                    'cancel' => array(
                        'fa-icon' => 'times',
                        'title' => __('Remove filters'),
                        'onClick' => 'cancelSearch',
                    )
                )
            )
        ),
        'fields' => array(
            array(
                'name' => __('ID'),
                'sort' => 'id',
                'element' => 'links',
                'class' => 'short',
                'data_path' => 'id',
                'url' => $baseurl . '/sharing_groups/view/%s'
            ),
            array(
                'name' => __('UUID'),
                'data_path' => 'uuid',
                'sort' => 'uuid',
                'class' => 'short quickSelect',
            ),
            array(
                'name' => __('Name'),
                'data_path' => 'name',
                'sort' => 'name',
                'class' => 'short',
            ),
            array(
                'name' => __('Creator'),
                'sort' => 'Organisation.name',
                'element' => 'org',
                'data_path' => 'Organisation',
                'class' => 'short',
            ),
            array(
                'name' => __('Description'),
                'data_path' => 'description',
            ),
            array(
                'name' => __('Org count'),
                'class' => 'short',
                'sort' => 'org_count',
                'data_path' => 'org_count',
            ),
            array(
                'name' => __('Releasable to'),
                'element' => 'custom',
                'function' => function (array $sharingGroup) use ($baseurl) {
                    $combined = __("Organisations:");
                    if (empty($sharingGroup['SharingGroupOrg'])) {
                        $combined .= "<br>N/A";
                    } else {
                        foreach ($sharingGroup['SharingGroupOrg'] as $sge) {
                            if (!empty($sge['Organisation'])) {
                                $combined .= "<br><a href='" . $baseurl . "/organisation/view/" . h($sge['Organisation']['id']) . "'>" . h($sge['Organisation']['name']) . "</a>";
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
                                $combined .= "<br><a href='" . $baseurl . "/server/view/" . h($sgs['Server']['id']) . "'>" . h($sgs['Server']['name']) . "</a>";
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
            )
        ),
        'actions' => array(
            array(
                'url' => $baseurl . '/sharing_groups/view',
                'url_params_data_paths' => ['id'],
                'icon' => 'eye',
                'title' => __('View Sharing Group'),
            ),
            array(
                'url' => '/sharing_groups/edit',
                'url_params_data_paths' => ['id'],
                'icon' => 'edit',
                'complex_requirement' => [
                    'function' => function (array $sharingGroup) {
                        return $sharingGroup['editable'];
                    }
                ],
                'title' => __('Edit Sharing Group'),
            ),
            array(
                'url' => '/sharing_groups/delete',
                'url_params_data_paths' => ['id'],
                'postLinkConfirm' => __('Are you sure you want to delete the sharing group?'),
                'icon' => 'trash',
                'complex_requirement' => [
                    'function' => function (array $sharingGroup) {
                        return $sharingGroup['deletable'];
                    }
                ],
                'title' => __('Delete Sharing Group'),
            ),
        )
    )
));
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
