<div class="row mb-4 mt-2">
    <div class="col-12">
        <div class="d-flex flex-column p-4">
            <p class="mb-0 text-secondary-emphasis">
                <?= __('You can find a list of communities below that chose to advertise their existence to the general MISP user-base. Requesting access to any of those communities is of course no guarantee of being permitted access, it is only meant to simplify the means of finding the various communities that one may be eligible for. Get in touch with the MISP project maintainers if you would like your community to be included in the list.') ?>
            </p>
        </div>
    </div>
</div>

<?php
$fields = [
    [
        'element' => 'selector',
        'data_path' => 'TaxiiServer.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/communities/view/%id%',
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'ajax',
                'label' => __('Request access'),
                'icon' => 'hand-holding-hand',
                'url' => $baseurl . '/communities/requestAccess/%id%',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'id',
        'element' => 'id',
        'url' => $baseurl . '/communities/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'uuid',
        'data_path' => 'uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/communities/view/%id%',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'name, description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [

        'name' => __('URL'),
        'sort' => 'url',
        'data_path' => 'url',
        'element' => 'links',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Host org'),
        'sort' => 'org_name',
        'data_path' => 'Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Vetted'),
        'sort' => 'misp_project_vetted',
        'data_path' => 'misp_project_vetted',
        'element' => 'vetted',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Self-reg'),
        'data_path' => 'url',
        'element' => 'self_registration',
        'title' => __('This community allows for self-registration'),
        'data_path_requirement' => 'self_registration',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ]
];


echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $community_list,
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
                ]
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/communities'
]);