<?php
// Header section
$headerTitle = __('Correlation Rules');
$headerDescription = __('Rules that block the creation of correlations between events matching the defined criteria.');

$headerActions = [];
if ($this->Acl->canAccess('correlationRules', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add correlation rule'),
        'icon' => 'plus',
        'url' => $baseurl . '/correlationRules/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$canEdit = $this->Acl->canAccess('correlationRules', 'edit');
$canDelete = $this->Acl->canAccess('correlationRules', 'delete');
$canExecute = $this->Acl->canAccess('correlationRules', 'executeRule');

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'CorrelationRule.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'CorrelationRule.id',
        'data_path' => 'CorrelationRule.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UUID'),
        'data_path' => 'CorrelationRule.uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'CorrelationRule.name',
        'data_path' => 'CorrelationRule.name, CorrelationRule.comment',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => 'CorrelationRule.selector_type',
        'data_path' => 'CorrelationRule.selector_type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Selectors'),
        'data_path' => 'CorrelationRule.selector_list',
        'element' => 'json',
        'card_section' => 'links',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'CorrelationRule.created',
        'data_path' => 'CorrelationRule.created',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Modified'),
        'sort' => 'CorrelationRule.timestamp',
        'data_path' => 'CorrelationRule.timestamp',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'CorrelationRule.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            $canExecute ? [
                'type' => 'modal',
                'label' => __('Execute rule on instance'),
                'icon' => 'rocket',
                'url' => $baseurl . '/correlationRules/executeRule/%id%',
            ] : null,
            $canEdit ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/correlationRules/edit/%id%',
            ] : null,
            $canDelete ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/correlationRules/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ]))
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
                        'button' => __('Search'),
                        'placeholder' => __('Search by name'),
                        'name'        => 'name',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/correlationRules'
]);
?>
