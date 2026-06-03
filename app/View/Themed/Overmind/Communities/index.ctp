<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('You can find a list of communities below that chose to advertise their existence to the general MISP user-base. Requesting access to any of those communities is of course no guarantee of being permitted access, it is only meant to simplify the means of finding the various communities that one may be eligible for. Get in touch with the MISP project maintainers if you would like your community to be included in the list.');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'id',
        'card_section' => 'selector',
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
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
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
                'type' => 'modal',
                'label' => __('Request access'),
                'icon' => 'hand-holding-hand',
                'url' => $baseurl . '/communities/requestAccess/%id%',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
];

/**
 * Scaffold
 */
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
            'primary_id_path' => 'id',
            'row_dblclick_url' => $baseurl . '/communities/view/%id%',
        ]
    ],
    'item_url' => '/communities'
]);