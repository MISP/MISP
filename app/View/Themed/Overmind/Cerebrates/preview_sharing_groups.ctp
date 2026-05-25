<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <h5 class="mb-1 fw-bold text-primary-emphasis">
                <?= __('Sharing Groups preview') ?>
            </h5>
            <p class="mb-0 text-secondary-emphasis">
                <?= __('Preview of the sharing groups known to the remote Cerebrate instance.') ?>
            </p>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'ajax',
                'label' => __('Fetch sharing group'),
                'icon' => 'download',
                'url' => $baseurl . '/cerebrates/download_sg/' . h($cerebrate['Cerebrate']['id']) . '/%id%',
            ]
        ]
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
        'name' => __('Status'),
        'sort' => 'exists_locally',
        'data_path' => '',
        'element' => 'remote_status',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'uuid',
        'data_path' => 'uuid',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name',
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
        'name' => __('Description'),
        'sort' => 'description',
        'data_path' => 'description',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('# Member'),
        'element' => 'custom',
        'function' => function($row) {
            return count($row['sharing_group_orgs']);
        },
        'card_section' => 'top',
        'display_in' => ['table', 'card']
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
    'item_url' => '/cerebrates/preview_sgs/' . h($cerebrate['Cerebrate']['id'])
]);
?>

<script type="text/javascript">
    var passedArgsArray = <?= json_encode([h($cerebrate['Cerebrate']['id'])]) ?>;
</script>