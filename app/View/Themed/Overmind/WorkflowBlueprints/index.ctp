<?php
// Header section
$headerTitle = __('Workflow Blueprints');
$headerDescription = __('Re-usable blocks of workflow logic that can be inserted into your workflows.');

$headerActions = [];
if ($this->Acl->canAccess('workflowBlueprints', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add workflow blueprint'),
        'icon' => 'plus',
        'url' => $baseurl . '/workflowBlueprints/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('workflowBlueprints', 'edit');
$canDelete = $this->Acl->canAccess('workflowBlueprints', 'delete');
$canExport = $this->Acl->canAccess('workflowBlueprints', 'export');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'WorkflowBlueprint.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'WorkflowBlueprint.id',
        'data_path' => 'WorkflowBlueprint.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'sort' => 'WorkflowBlueprint.uuid',
        'data_path' => 'WorkflowBlueprint.uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'WorkflowBlueprint.name',
        'data_path' => 'WorkflowBlueprint.name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Default'),
        'sort' => 'WorkflowBlueprint.default',
        'data_path' => 'WorkflowBlueprint.default',
        'element' => 'flag',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Description'),
        'sort' => 'WorkflowBlueprint.description',
        'data_path' => 'WorkflowBlueprint.description',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Timestamp'),
        'sort' => 'WorkflowBlueprint.timestamp',
        'data_path' => 'WorkflowBlueprint.timestamp',
        'element' => 'datetime',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'WorkflowBlueprint.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/workflowBlueprints/view/%id%',
            ],
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/workflowBlueprints/edit/%id%',
            ] : null,
            $canExport ? [
                'type' => 'navigate',
                'label' => __('Export'),
                'icon' => 'download',
                'url' => $baseurl . '/workflowBlueprints/export/%id%',
                'download' => true,
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/workflowBlueprints/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ]))
    ]
];

$filterBar = [
    'pull' => 'right',
    'children' => [
        [
            'type' => 'search',
            'button' => __('Search'),
            'placeholder' => __('Search by name or UUID'),
            'mode' => 'quickFilter',
        ],
    ],
];
if ($canDelete) {
    $filterBar['delete'] = '/deleteSelection';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => $filterBar,
            'fields' => $fields,
        ]
    ],
    'item_url' => '/workflowBlueprints'
]);
?>
