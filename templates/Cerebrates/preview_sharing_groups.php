<?php
$fields = [
    [
        'name' => __('Id'),
        'sort' => 'id',
        'data_path' => 'id',
    ],
    [
        'name' => __('Status'),
        'sort' => 'exists_locally',
        'element' => 'remote_status',
        'data_path' => '',
    ],
    [
        'name' => __('UUID'),
        'sort' => 'uuid',
        'data_path' => 'uuid',
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name',
    ],
    [
        'name' => __('Releasability'),
        'sort' => 'releasability',
        'data_path' => 'releasability',
    ],
    [
        'name' => __('Description'),
        'sort' => 'description',
        'data_path' => 'description',
    ],
    [
        'name' => __('# Member'),
        'element' => 'custom',
        'function' => function ($row) {
            return count($row['sharing_group_orgs']);
        },
    ],
];

echo $this->element(
    'genericElements/IndexTable/index_table',
    [
        'data' => [
            'data' => $data,
            'top_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'preserve_url_params' => [$cerebrate['id']],
                        'searchKey' => 'quickFilter',
                    ],
                ],
            ],
            'fields' => $fields,
            'title' => empty($ajax) ? __(
                'Sharing group list via Cerebrate {0} ({1})',
                h($cerebrate['id']),
                h($cerebrate['name'])
            ) : false,
            'description' => empty($ajax) ? __('Preview of the sharing group known to the remote Cerebrate instance.') : false,
            'actions' => [
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/cerebrates/download_sg/%d/[onclick_params_data_path]\');',
                        $baseurl,
                        h($cerebrate['id'])
                    ),
                    'onclick_params_data_path' => 'id',
                    'icon' => 'download',
                    'title' => __('Fetch sharing group object'),
                ],
            ],
            'paginatorOptions' => array_merge(
                ['url' => [$cerebrate['id']]],
                $passedParams
            ),
            'persistUrlParams' => [0, 'quickFilter'],
        ],
        'containerId' => 'preview_sgs_container',
    ]
);
?>
<script type="text/javascript">
    var passedArgsArray = <?= json_encode([h($cerebrate['id'])]) ?>;
</script>
