<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('Linked TAXII Servers');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('You can connect your MISP to one or several TAXII servers to push data to using a set of filters.');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('taxiiServers', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add TaxiiServers'),
        'icon' => 'plus',
        'url' => $baseurl . '/taxiiServers/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);



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
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/taxiiServers/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/taxiiServers/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'modal',
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
                'type' => 'modal',
                'label' => __('Push all filtered data to TAXII server'),
                'icon' => 'arrow-circle-up',
                'url' => $baseurl . '/taxiiServers/push/%id%',
                'requirement' => $isSiteAdmin
            ]
        ]
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