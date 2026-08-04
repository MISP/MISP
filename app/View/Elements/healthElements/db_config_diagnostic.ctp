<div>
    <?= $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $dbConfiguration,
            'skip_pagination' => 1,
            'fields' => array(
                array(
                    'name' => __('Setting'),
                    'data_path' => 'name'
                ),
                array(
                    'name' => __('Default'),
                    'class' => 'align-left',
                    'header_class' => 'align-left',
                    'data_path' => 'default'
                ),
                array(
                    'name' => __('Current'),
                    'class' => 'align-left',
                    'header_class' => 'align-left',
                    'data_path' => 'value',
                ),
                array(
                    'name' => __('Recommended'),
                    'class' => 'align-left',
                    'header_class' => 'align-left',
                    'data_path' => 'recommended'
                ),
                array(
                    'name' => __('Explanation'),
                    'header_class' => 'align-left',
                    'data_path' => 'explanation'
                ),
            ),
            'title' => __('SQL database configuration'),
            'description' => __('Best practices for configuring RDBMS parameters for performance.'),
        )
    ));
    ?>
</div>