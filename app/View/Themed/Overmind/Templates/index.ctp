<?php

$fields = [
    [
        'element' => 'selector',
        'data_path' => 'Template.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/templates/view/%id%'
            ],
            [
                'type' => 'ajax',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/templates/edit/%id%',
                'requirement' => $me['Role']['perm_template']
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/templates/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_template']
            ]
        ]
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
    ]
];

/**
 * Header actions (optionnel)
 */
if ($this->Acl->canAccess('templates', 'add')) {
    $this->set('headerActions', [
        [
            'type' => 'ajax',
            'label' => __('Add Template'),
            'url' => $baseurl . '/templates/add',
            'icon' => 'plus'
        ]
    ]);
}

/**
 * Scaffold
 */
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
        ]
    ],
    'item_url' => '/templates'
]);

?>