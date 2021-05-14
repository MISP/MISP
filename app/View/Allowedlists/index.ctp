<div class="allowedlist index">
<?php
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $list,
            'title' =>__('Signature Allowedlist'),
            'description' => __('Regex entries (in the standard php regex /{regex}/{modifier} format) entered below will restrict matching attributes from being included in the IDS flag sensitive exports (such as NIDS exports).'),
            'primary_id_path' => 'Allowedlist.id',
            'fields' => array(
                array(
                    'name' => __('ID'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'Allowedlist.id',
                    'element' => 'links',
                    'url' => $baseurl . '/allowedlists/view/%s'
                ),
                array(
                    'name' => __('Name'),
                    'sort' => 'name',
                    'data_path' => 'Allowedlist.name',
                ),
            ),
            'actions' => array(
                array(
                    'url' => $baseurl . '/admin/allowedlists/edit',
                    'url_params_data_paths' => array(
                        'Allowedlist.id'
                    ),
                    'icon' => 'edit'
                ),
                array(
                    'title' => __('Delete'),
                    'url' => $baseurl . '/admin/allowedlists/delete',
                    'url_params_data_paths' => array(
                        'Allowedlist.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the entry?'),
                    'icon' => 'trash',
                    'requirements' => $isSiteAdmin,
                ),
            )
        )
    ));
    ?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'allowedlist', 'menuItem' => 'index')); ?>