<?php

$fields = [
    [
        'element' => 'selector',
        'data_path' => 'EventTemplate.id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'link',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/event_templates/view/%id%',
            ],
            [
                'type' => 'link',
                'label' => __('Create event from template'),
                'icon' => 'play',
                'url' => $baseurl . '/event_templates/instantiate/%id%',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'instantiate'),
            ],
            [
                'type' => 'link',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/event_templates/edit/%id%',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'edit'),
            ],
            [
                'type' => 'ajax',
                'label' => __('Duplicate'),
                'icon' => 'copy',
                'url' => $baseurl . '/event_templates/duplicate/%id%',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'duplicate'),
            ],
            [
                'type' => 'link',
                'label' => __('Export'),
                'icon' => 'download',
                'url' => $baseurl . '/event_templates/export/%id%',
            ],
            [
                'type' => 'divider',
                'url' => '#',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'delete'),
            ],
            [
                'type' => 'ajax',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/event_templates/delete/%id%',
                'class' => 'text-danger',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'delete'),
            ],
        ],
    ],
    [
        'name' => __('ID'),
        'sort' => 'EventTemplate.id',
        'data_path' => 'EventTemplate.id',
        'element' => 'id',
        'url' => $baseurl . '/event_templates/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Name'),
        'sort' => 'EventTemplate.name',
        'data_path' => 'EventTemplate.name',
        'element' => 'generic_field',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('UUID'),
        'sort' => 'EventTemplate.uuid',
        'data_path' => 'EventTemplate.uuid',
        'element' => 'uuid',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Organisation.name',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Distribution'),
        'sort' => 'EventTemplate.distribution',
        'data_path' => 'EventTemplate.distribution',
        'element' => 'distribution',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Active'),
        'sort' => 'EventTemplate.active',
        'data_path' => 'EventTemplate.active',
        'element' => 'boolean',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Version'),
        'sort' => 'EventTemplate.version',
        'data_path' => 'EventTemplate.version',
        'element' => 'version',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Modified'),
        'sort' => 'EventTemplate.modified',
        'data_path' => 'EventTemplate.modified',
        'element' => 'timestamp',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
];

$headerActions = [];
if ($this->Acl->canAccess('eventTemplates', 'add')) {
    $headerActions[] = [
        'type' => 'link',
        'label' => __('Add Event Template'),
        'icon' => 'plus',
        'url' => $baseurl . '/event_templates/add',
    ];
}
if ($this->Acl->canAccess('eventTemplates', 'import')) {
    $headerActions[] = [
        'type' => 'link',
        'label' => __('Import'),
        'icon' => 'upload',
        'url' => $baseurl . '/event_templates/import',
    ];
}
$this->set('headerActions', $headerActions);

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $list,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by name, UUID, or description'),
                        'name' => 'searchall',
                        'mode' => 'quickFilter',
                    ],
                ],
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/event_templates',
]);
