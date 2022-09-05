<div class="threads index">
    <?php
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $threads,
            'title' => __('Discussions'),
            'primary_id_path' => 'Thread.id',
            'fields' => array(
                array(
                    'name' => __('Org'),
                    'sort' => 'Organisation.name',
                    'data_path' => 'Organisation',
                    'element' => 'org'
                ),
                array(
                    'name' => __('Title'),
                    'sort' => 'Thread.title',
                    'data_path' => 'Thread.title',
                ),
                array(
                    'name' => __('Last Post On'),
                    'sort' => 'Thread.date_modified',
                    'data_path' => 'Thread.date_modified',
                ),
                array(
                    'name' => __('Last Post By'),
                    'sort' => 'User.email',
                    'data_path' => 'User.email',
                ),
                array(
                    'name' => __('Thread Started On'),
                    'sort' => 'Thread.date_created',
                    'data_path' => 'Thread.date_created',
                ),
                array(
                    'name' => __('Posts'),
                    'sort' => 'Thread.post_count',
                    'data_path' => 'Thread.post_count',
                ),
                array(
                    'name' => __('Distribution'),
                    'sort' => 'Thread.distribution',
                    'data_path' => 'Thread.distribution',
                    'element' => 'distribution_levels'
                ),
            ),
            'actions' => array(
                array(
                    'url' => $baseurl . '/threads/view',
                    'url_params_data_paths' => array(
                        'Thread.id'
                    ),
                    'icon' => 'eye'
                )
            )
        )
    ));
    ?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'threads', 'menuItem' => 'index')); ?>
