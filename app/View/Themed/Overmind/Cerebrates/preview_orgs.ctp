<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <h5 class="mb-1 fw-bold text-primary-emphasis">
                <?= __('Organisations preview') ?>
            </h5>
            <p class="mb-0 text-secondary-emphasis">
                <?= __('Preview of the organisations known to the remote Cerebrate instance.') ?>
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
                'type' => 'modal',
                'label' => __('Fetch organisation'),
                'icon' => 'download',
                'url' => $baseurl . '/cerebrates/download_org/' . h($cerebrate['Cerebrate']['id']) . '/%id%',
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
    ]
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