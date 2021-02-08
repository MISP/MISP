<div class="taxonomies index">
<?= $this->element('/genericElements/IndexTable/index_table', ['data' => array(
    'title' => __('Taxonomies'),
    'data' => $taxonomies,
    'top_bar' => array(
        'children' => array(
            array(
                'type' => 'simple',
                'children' => array(
                    array(
                        'url' => $baseurl . '/taxonomies/index',
                        'text' => __('All'),
                        'active' => !isset($passedArgsArray['enabled']),
                    ),
                    array(
                        'url' => $baseurl . '/taxonomies/index/enabled:1',
                        'text' => __('Enabled'),
                        'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "1",
                    ),
                    array(
                        'url' => $baseurl . '/taxonomies/index/enabled:0',
                        'text' => __('Disabled'),
                        'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "0",
                    )
                )
            ),
            array(
                'type' => 'search',
                'button' => __('Filter'),
                'placeholder' => __('Enter value to search'),
                'searchKey' => 'value',
            )
        )
    ),
    'fields' => array(
        array(
            'name' => __('ID'),
            'sort' => 'id',
            'class' => 'short',
            'data_path' => 'Taxonomy.id'
        ),
        array(
            'name' => __('Namespace'),
            'sort' => 'namespace',
            'class' => 'short',
            'data_path' => 'Taxonomy.namespace'
        ),
        array(
            'name' => __('Description'),
            'sort' => 'description',
            'data_path' => 'Taxonomy.description'
        ),
        array(
            'name' => __('Version'),
            'sort' => 'version',
            'class' => 'short',
            'data_path' => 'Taxonomy.version'
        ),
        array(
            'name' => __('Enabled'),
            'element' => 'boolean',
            'sort' => 'enabled',
            'class' => 'short',
            'data_path' => 'Taxonomy.enabled',
        ),
        array(
            'name' => __('Required'),
            'element' => 'toggle',
            'url' => $baseurl . '/taxonomies/toggleRequired',
            'url_params_data_paths' => array(
                'Taxonomy.id'
            ),
            'sort' => 'required',
            'class' => 'short',
            'data_path' => 'Taxonomy.required'
        ),
        array(
            'name' => __('Active Tags'),
            'element' => 'custom',
            'class' => 'shortish',
            'function' => function (array $item) use ($isSiteAdmin) {
                $content = '<strong>' . h($item['current_count']) . '</strong> / ' . h($item['total_count']);
                if ($item['current_count'] != $item['total_count'] && $isSiteAdmin && $item['Taxonomy']['enabled']) {
                    $content .= ' (' . $this->Form->postLink(__('enable all'), array('action' => 'addTag', h($item['Taxonomy']['id'])), array('title' => __('Enable all tags')), __('Are you sure you want to enable every tag associated to this taxonomy?')) . ')';
                }
                return $content;
            }
        ),
    ),
    'actions' => array(
        array(
            'title' => __('Enable'),
            'icon' => 'play',
            'postLink' => true,
            'url' => $baseurl . '/taxonomies/enable',
            'url_params_data_paths' => ['Taxonomy.id'],
            'postLinkConfirm' => __('Are you sure you want to enable this taxonomy library?'),
            'complex_requirement' => array(
                'function' => function ($row, $options) use ($isSiteAdmin) {
                    return $isSiteAdmin && !$options['datapath']['enabled'];
                },
                'options' => array(
                    'datapath' => array(
                        'enabled' => 'Taxonomy.enabled'
                    )
                )
            ),
        ),
        array(
            'title' => __('Disable'),
            'icon' => 'stop',
            'postLink' => true,
            'url' => $baseurl . '/taxonomies/disable',
            'url_params_data_paths' => ['Taxonomy.id'],
            'postLinkConfirm' => __('Are you sure you want to disable this taxonomy library?'),
            'complex_requirement' => array(
                'function' => function ($row, $options) use ($isSiteAdmin) {
                    return $isSiteAdmin && $options['datapath']['enabled'];
                },
                'options' => array(
                    'datapath' => array(
                        'enabled' => 'Taxonomy.enabled'
                    )
                )
            ),
        ),
        array(
            'onclick' => "deleteObject('taxonomies', 'delete', '[onclick_params_data_path]', '[onclick_params_data_path]');",
            'onclick_params_data_path' => 'Taxonomy.id',
            'icon' => 'trash',
            'title' => __('Delete taxonomy'),
            'requirement' => $isSiteAdmin,
        ),
        array(
            'url' => $baseurl . '/taxonomies/view',
            'url_params_data_paths' => array(
                'Taxonomy.id'
            ),
            'icon' => 'eye',
            'title' => __('View taxonomy'),
            'dbclickAction' => true,
        )
    )
)
]);
?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'index'));
