<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <h5 class="mb-1 fw-bold text-primary-emphasis"><?= __('Linked TAXII Servers') ?></h5>
            <p class="mb-0 text-secondary-emphasis">
                <?= __('You can connect your MISP to one or several TAXII servers to push data to using a set of filters.') ?>
            </p>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'TaxiiServer.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'TaxiiServer.id',
        'data_path' => 'TaxiiServer.id',
        'element' => 'id',
        'url' => $baseurl . '/taxiiServers/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'TaxiiServer.uuid',
        'data_path' => 'TaxiiServer.uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/taxiiServers/view/%id%',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'TaxiiServer.name',
        'data_path' => 'TaxiiServer.name, TaxiiServer.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [

        'name' => __('Base URL'),
        'sort' => 'TaxiiServer.baseurl',
        'data_path' => 'TaxiiServer.baseurl',
        'element' => 'links',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner'),
        'sort' => 'TaxiiServer.owner',
        'data_path' => 'TaxiiServer.owner',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Skip Proxy'),
        'sort' => 'TaxiiServer.skip_proxy',
        'data_path' => 'TaxiiServer.skip_proxy',
        'element' => 'proxy',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'TaxiiServer.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/taxiiServers/view/%id%',
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/taxiiServers/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/taxiiServers/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Push all filtered data to TAXII server'),
                'icon' => 'arrow-circle-up',
                'url' => $baseurl . '/taxiiServers/push/%id%',
                'requirement' => $isSiteAdmin
            ]
        ]
    ]
];

if ($this->Acl->canAccess('taxiiServers', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add TaxiiServers'),
            'icon' => 'plus',
            'url' => $baseurl . '/taxiiServers/add'
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
            ],
            'fields' => $fields,
            'primary_id_path' => 'TaxiiServer.id',
            'row_dblclick_url' => $baseurl . '/taxiiServers/view/%id%',
        ]
    ],
    'item_url' => '/taxiiServers'
]);