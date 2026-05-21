<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('objectTemplates', 'update')) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Update Object'),
        'icon' => 'sync',
        'url' => $baseurl . '/objectTemplates/update'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'ObjectTemplate.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'ObjectTemplate.id',
        'data_path' => 'ObjectTemplate.id',
        'element' => 'id',
        'url' => $baseurl . '/objectTemplates/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'ObjectTemplate.uuid',
        'data_path' => 'ObjectTemplate.uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/objectTemplates/view/%id%',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'ObjectTemplate.name',
        'data_path' => 'ObjectTemplate.name, ObjectTemplate.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Meta-category'),
        'sort' => 'ObjectTemplate.meta-category',
        'data_path' => 'ObjectTemplate.meta-category',
        'element' => 'category',
        'card_section' => 'category',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'ObjectTemplate.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Active'),
        'sort' => 'ObjectTemplate.active',
        'data_path' => 'ObjectTemplate.active',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Requirements'),
        'data_path' => 'ObjectTemplate.requirements',
        'element' => 'object_template_requirements',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'ObjectTemplate.id',
        'active_path' => 'ObjectTemplate.active',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/objectTemplates/view/%id%'
            ],
            [
                'type' => 'navigate',
                'label' => __('Force update'),
                'icon' => 'sync',
                'url' => $baseurl . '/objectTemplates/update/%name%/%id%',
                'url_params_data_paths' => ['name' => 'ObjectTemplate.name'],
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/objectTemplates/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'toggle',
                'label_on' => __('Deactivate'),
                'label_off' => __('Activate'),
                'icon_on' => 'stop text-danger',
                'icon_off' => 'play text-success',
                'url' => '/objectTemplates/%action%/%id%',
                'active_path' => 'ObjectTemplate.active',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
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
                        'name'        => 'searchall',
                        'mode'        => 'legacy',
                    ],
                ],
                'delete' => '/deleteSelection',
                'active' => 1,
            ],
            'fields' => $fields,
            'primary_id_path' => 'ObjectTemplate.id',
            'row_dblclick_url' => $baseurl . '/objectTemplates/view/%id%',
        ]
    ],
    'item_url' => '/objectTemplates'
]);