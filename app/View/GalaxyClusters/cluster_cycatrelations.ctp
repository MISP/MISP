<?php
    $cycatUrl = empty(Configure::read('Plugin.CyCat_url')) ? 'https://api.cycat.org' : Configure::read('Plugin.CyCat_url');
    $CyCatRelationsTable = $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'skip_pagination' => true,
            'data' => $CyCatRelations,
            'fields' => [
                [
                    'name' => __('UUID'),
                    'class' => 'short',
                    'data_path' => 'uuid',
                    'element' => 'links',
                    'url_params_data_paths' => 'uuid',
                    'url' => $cycatUrl . '/lookup'
                ],
                [
                    'name' => __('MITRE CTI Name'),
                    'class' => 'short',
                    'data_path' => 'mitre-cti:name',
                ],
                [
                    'name' => __('MITRE CTI Type'),
                    'class' => 'short',
                    'data_path' => 'mitre-cti:type',
                ],
                [
                    'name' => __('MITRE CTI Description'),
                    'data_path' => 'mitre-cti:description',
                ],
            ],
        ]
    ]);
    echo $CyCatRelationsTable;
?>
