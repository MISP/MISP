<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('templates', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Template'),
        'url' => $baseurl . '/templates/add',
        'icon' => 'plus'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Template.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Template.id',
        'data_path' => 'Template.id',
        'element' => 'id',
        'url' => $baseurl . '/templates/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Template.name',
        'data_path' => 'Template.name, Template.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Shared'),
        'sort' => 'Template.share',
        'data_path' => 'Template.share',
        'element' => 'shared',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Template.org',
        'data_path' => 'Template.org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Template.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/templates/view/%id%'
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/templates/edit/%id%',
                'requirement' => $me['Role']['perm_template']
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/templates/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_template']
            ]
        ]
    ]
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $list,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
            'primary_id_path' => 'Template.id',
            'row_dblclick_url' => $baseurl . '/templates/view/%id%',
        ]
    ],
    'item_url' => '/templates'
]);

?>