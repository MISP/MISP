<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <h5 class="mb-1 fw-bold text-primary-emphasis"><?= __('Linked Cerebrates') ?></h5>
            <p class="mb-0 text-secondary-emphasis">
                <?= __('You can connect your MISP to one or several Cerebrate instances to act as lookup directories for organisation and sharing group information.') ?>
            </p>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Cerebrate.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Cerebrate.id',
        'data_path' => 'Cerebrate.id',
        'element' => 'id',
        'url' => $baseurl . '/cerebrates/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Cerebrate.name',
        'data_path' => 'Cerebrate.name, Cerebrate.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [

        'name' => __('URL'),
        'sort' => 'Cerebrate.url',
        'data_path' => 'Cerebrate.url',
        'element' => 'links',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Organisation',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Skip Proxy'),
        'sort' => 'Cerebrate.skip_proxy',
        'data_path' => 'Cerebrate.skip_proxy',
        'element' => 'proxy',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Pull Orgs'),
        'sort' => 'Cerebrate.pull_orgs',
        'data_path' => 'Cerebrate.pull_orgs',
        'element' => 'pull',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Pull SGs'),
        'sort' => 'Cerebrate.pull_sharing_groups',
        'data_path' => 'Cerebrate.pull_sharing_groups',
        'element' => 'pull',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Cerebrate.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/cerebrates/view/%id%',
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/cerebrates/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/cerebrates/deleteSelection/%id%',
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
                'label' => __('Pull all organisations'),
                'icon' => 'arrow-circle-down text-warning',
                'url' => $baseurl . '/cerebrates/pull_orgs/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Pull all sharing groups'),
                'icon' => 'arrow-circle-down text-object-dark',
                'url' => $baseurl . '/cerebrates/pull_sgs/%id%',
                'requirement' => $isSiteAdmin
            ]
        ]
    ]
];

if ($this->Acl->canAccess('cerebrates', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add Cerebrates'),
            'icon' => 'plus',
            'url' => $baseurl . '/cerebrates/add'
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
            'primary_id_path' => 'Cerebrate.id',
            'row_dblclick_url' => $baseurl . '/cerebrates/view/%id%',
        ]
    ],
    'item_url' => '/cerebrates'
]);