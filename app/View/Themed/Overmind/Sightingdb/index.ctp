<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <h5 class="mb-1 fw-bold text-primary-emphasis"><?= __('SightingDB Configuration') ?></h5>
            <p class="mb-0 text-secondary-emphasis">
                <?= __('SightingDB is an alternate database that MISP interconnects with to track indicator sightings. Manage your remote connections and synchronization settings below.') ?>
            </p>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Sightingdb.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Sightingdb.id',
        'data_path' => 'Sightingdb.id',
        'element' => 'id',
        'url' => '',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Sightingdb.name',
        'data_path' => 'Sightingdb.name, Sightingdb.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [

        'name' => __('Host'),
        'sort' => 'Sightingdb.host',
        'data_path' => 'Sightingdb.host, Sightingdb.port',
        'element' => 'host_port',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Namespace'),
        'sort' => 'Sightingdb.namespace',
        'data_path' => 'Sightingdb.namespace',
        'element' => 'namespace',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner'),
        'sort' => 'Sightingdb.owner',
        'data_path' => 'Sightingdb.owner',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Sightingdb.enabled',
        'data_path' => 'Sightingdb.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Skip Proxy'),
        'sort' => 'Sightingdb.skip_proxy',
        'data_path' => 'Sightingdb.skip_proxy',
        'element' => 'proxy',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Skip SSL'),
        'sort' => 'Sightingdb.ssl_skip_verification',
        'data_path' => 'Sightingdb.ssl_skip_verification',
        'element' => 'ssl',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Org restrictions'),
        'data_path' => 'Sightingdb.org_id',
        'element' => 'id',
        'url' => $baseurl . '/organisations/view/%id%',
        'card_section' => 'meta',
        'display_in' => ['table','card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Sightingdb.id',
        'active_path' => 'Sightingdb.active',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/sightingdb/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/sightingdb/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ],
        ]
    ],
];

if ($this->Acl->canAccess('sightingdb', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add SightingDB'),
            'icon' => 'plus',
            'url' => $baseurl . '/sightingdb/add'
        ]
    ]);
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search in all fields',
                        'name'        => '',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection',
                'active' => 1,
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/sightingdb'
]);