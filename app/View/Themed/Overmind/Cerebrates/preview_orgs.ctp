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
        'element' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'uuid',
        'data_path' => 'uuid',
        'element' => 'uuid',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Sector'),
        'sort' => 'sector',
        'data_path' => 'sector',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Nationality'),
        'sort' => 'nationality',
        'data_path' => 'nationality',
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
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Fetch organisation'),
                'icon' => 'download',
                'url' => $baseurl . '/cerebrates/download_org/' . h($cerebrate['Cerebrate']['id']) . '/%id%',
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
    'item_url' => '/cerebrates/preview_orgs/' . h($cerebrate['Cerebrate']['id'])
]);
?>

<script type="text/javascript">
    var passedArgsArray = <?= json_encode([h($cerebrate['Cerebrate']['id'])]) ?>;
</script>