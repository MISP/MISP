
<?php
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],

    [
        'name' => __('UUID'),
        'sort' => 'uuid',
        'data_path' => 'uuid',
        'element' => 'uuid',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name, description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Releasability'),
        'sort' => 'releasability',
        'data_path' => 'releasability',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Status'),
        'sort' => 'exists_locally',
        'data_path' => '',
        'element' => 'remote_status',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('# Member'),
        'element' => 'count',
        'data_path' => 'sharing_group_orgs.{n}.uuid',
        'tally' => true,
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Fetch sharing group'),
                'icon' => 'download',
                'url' => $baseurl . '/cerebrates/download_sg/' . h($cerebrate['Cerebrate']['id']) . '/%id%',
                'size' => 'md',
                'requirement' => $isSiteAdmin,
            ],
        ],
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'name' => '',
                        'mode' => 'quickFilter',
                    ],
                ],
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/cerebrates/preview_sharing_groups/' . h($cerebrate['Cerebrate']['id'])
]);
?>

<script type="text/javascript">
    var passedArgsArray = <?= json_encode([h($cerebrate['Cerebrate']['id'])]) ?>;
</script>