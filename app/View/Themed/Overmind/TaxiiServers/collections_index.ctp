<?php
// Standalone (full-page) header — ignored when loaded as an ajax tab fragment.
$this->set('headerTitle', __('Collections on TAXII Server #%s', h($id)));
?>
<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <h5 class="mb-1 fw-bold text-primary-emphasis">
                <?= __('Collections') ?>
            </h5>
            <p class="mb-0 text-secondary-emphasis">
                <?= __('The collections advertised by the remote TAXII server.') ?>
            </p>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Title'),
        'sort' => 'title',
        'data_path' => 'title',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Description'),
        'data_path' => 'description',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Writeable'),
        'sort' => 'can_write',
        'data_path' => 'can_write',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Readable'),
        'sort' => 'can_read',
        'data_path' => 'can_read',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Media types'),
        'data_path' => 'media_types',
        'element' => 'format_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('Browse objects'),
                'icon' => 'eye',
                'url' => $baseurl . '/taxiiServers/objectsIndex/' . h($id) . '/%id%',
            ]
        ]
    ]
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'skip_pagination' => 1,
            'data' => $data,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/taxiiServers/collectionsIndex/' . h($id)
]);
