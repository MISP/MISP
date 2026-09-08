<?php
// Standalone (full-page) header — ignored when loaded as an ajax tab fragment.
$this->set('headerTitle', __('Objects in Collection %s on TAXII Server #%s', h($collection_id), h($id)));

$next_url = '';
if (!empty($more)) {
    $next_url = $baseurl . '/taxiiServers/objectsIndex/' . h($id) . '/' . h($collection_id) . '/' . h($next);
}
?>
<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-wrap justify-content-between align-items-center p-4 gap-2">
            <div class="d-flex flex-column">
                <h5 class="mb-1 fw-bold text-primary-emphasis">
                    <?= __('Objects in selected collection') ?>
                </h5>
                <p class="mb-0 text-secondary-emphasis">
                    <?= __('STIX objects retrieved from the remote TAXII collection.') ?>
                </p>
            </div>
            <?php if (!empty($more)): ?>
                <a href="<?= h($next_url) ?>" class="btn btn-primary flex-shrink-0">
                    <i class="fas fa-arrow-right me-1"></i><?= __('Next page') ?>
                </a>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'name' => __('ID'),
        'data_path' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'data_path' => 'type',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'data_path' => 'created',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Modified'),
        'data_path' => 'modified',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Labels'),
        'data_path' => 'labels',
        'element' => 'format_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('STIX version'),
        'data_path' => 'spec_version',
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
                'label' => __('View raw STIX object'),
                'icon' => 'eye',
                'url' => $baseurl . '/taxiiServers/objectView/' . h($id) . '/' . h($collection_id) . '/%id%',
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
    'item_url' => '/taxiiServers/objectsIndex/' . h($id) . '/' . h($collection_id)
]);
