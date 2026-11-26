<?php
// Standalone (full-page) header — ignored when loaded as an ajax tab fragment.
$this->set('headerTitle', __('Objects in Collection %s on TAXII Server #%s', h($collection_id), h($id)));
$this->set('headerDescription', __('STIX objects retrieved from the remote TAXII collection.'));

$next_url = '';
if (!empty($more)) {
    $next_url = $baseurl . '/taxiiServers/objectsIndex/' . h($id) . '/' . h($collection_id) . '/' . h($next);
}
?>
<?php if (!empty($more)): ?>
    <div class="d-flex justify-content-end px-4 pb-3">
        <a href="<?= h($next_url) ?>" class="btn btn-primary">
            <i class="fas fa-arrow-right me-1"></i><?= __('Next page') ?>
        </a>
    </div>
<?php endif; ?>

<?php
if (!empty($remoteNotice)) {
    echo $this->element('TaxiiServers/View/taxiiServers_remote_notice', [
        'notice' => $remoteNotice,
    ]);
    return;
}

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
