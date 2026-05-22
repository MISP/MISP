<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <p class="mb-0 text-secondary-emphasis">
                <?= __('Organisations that would end up in a sharing group with the current SharingGroupBlueprint blueprint.') ?>
            </p>
        </div>
    </div>
</div>


<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Organisation.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/organisation/view/%id%',
            ]
        ]
    ],
    [
        'name' => __('ID'),
        'sort' => 'Organisation.id',
        'data_path' => 'Organisation.id',
        'element' => 'id',
        'url' => $baseurl . '/organisation/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'Organisation.uuid',
        'data_path' => 'Organisation.uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/organisation/view/%id%',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation.name',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Sector'),
        'sort' => 'Organisation.sector',
        'data_path' => 'Organisation.sector',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => 'Organisation.type',
        'data_path' => 'Organisation.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Nationality'),
        'sort' => 'Organisation.nationality',
        'data_path' => 'Organisation.nationality',
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
                ],
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/organisations'
]);