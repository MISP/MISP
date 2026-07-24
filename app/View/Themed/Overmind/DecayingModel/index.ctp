<?php

$headerTitle = __('Decaying Models');
$headerDescription = __('Scoring models that let indicators lose relevance over time. Tune, assign and share them across your organisation.');

$canUpdate = $this->Acl->canAccess('decayingModel', 'update');
$canAdd    = $this->Acl->canAccess('decayingModel', 'add');
$canImport = $this->Acl->canAccess('decayingModel', 'import');

$headerActions = [];
if ($canUpdate) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Force update defaults'),
        'icon' => 'bolt',
        'url' => $baseurl . '/decayingModel/update/true',
        'confirm' => __('Force update will overwrite every default model, discarding local edits made to them. Continue?'),
    ];

    $headerActions[] = [
        'type' => 'action',
        'label' => __('Update defaults'),
        'icon' => 'rotate',
        'url' => $baseurl . '/decayingModel/update',
        'confirm' => __('Update the default decaying models shipped with MISP? Local, non-default models are left untouched.'),
    ];
}
if ($canImport) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Import'),
        'icon' => 'file-import',
        'url' => $baseurl . '/decayingModel/import',
    ];
}
if ($canAdd) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add model'),
        'icon' => 'plus',
        'url' => $baseurl . '/decayingModel/add',
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$sortSuffix = '';
if (!empty($passedArgsArray['sort'])) {
    $sortSuffix .= '/sort:' . h($passedArgsArray['sort']);
}
if (!empty($passedArgsArray['direction'])) {
    $sortSuffix .= '/direction:' . h($passedArgsArray['direction']);
}
$base = $baseurl . '/decayingModel/index';
$isMy = !empty($passedArgsArray['my_models']);
$isShared = !empty($passedArgsArray['all_orgs']);
$isDefault = !empty($passedArgsArray['default_models']);
$scopeBtn = function ($active) {
    return $active ? 'btn btn-primary' : 'btn btn-outline-primary';
};


$canEditRow = function ($row) use ($me) {
    $dm = $row['DecayingModel'];
    return !empty($me['Role']['perm_site_admin']) || (
        !empty($me['Role']['perm_decaying']) &&
        empty($dm['default']) &&
        $dm['org_id'] == $me['org_id']
    );
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'DecayingModel.id',
        'enable_path' => 'DecayingModel.enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'DecayingModel.id',
        'data_path' => 'DecayingModel.id',
        'element' => 'id',
        'url' => $baseurl . '/decayingModel/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'DecayingModel.name',
        'data_path' => 'DecayingModel.name, DecayingModel.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'DecayingModel.org_id',
        'data_path' => 'Organisation',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Formula'),
        'sort' => 'DecayingModel.formula',
        'data_path' => 'DecayingModel.formula',
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function ($row) use ($available_formulas) {
            $formula = $row['DecayingModel']['formula'];
            $html = '<span class="badge bg-info-subtle text-info-emphasis border border-info-subtle">'
                . h($formula) . '</span>';
            if (!empty($available_formulas[$formula]['description'])) {
                $html .= ' <i class="fas fa-circle-question text-muted" title="'
                    . h($available_formulas[$formula]['description']) . '"></i>';
            }
            return $html;
        },
    ],
    [
        'name' => __('Default'),
        'sort' => 'DecayingModel.default',
        'data_path' => 'DecayingModel.default',
        'element' => 'default',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'DecayingModel.enabled',
        'data_path' => 'DecayingModel.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Version'),
        'sort' => 'DecayingModel.version',
        'data_path' => 'DecayingModel.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('# Assigned Types'),
        'data_path' => 'DecayingModel.attribute_type_count',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'DecayingModel.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/decayingModel/view/%id%',
            ],
            [
                'type' => 'navigate',
                'label' => __('Download JSON'),
                'icon' => 'cloud-arrow-down',
                'url' => $baseurl . '/decayingModel/export/%id%.json',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/decayingModel/edit/%id%',
                'requirement' => $canEditRow,
            ],
            [
                'type' => 'postLink',
                'label' => __('Enable'),
                'icon' => 'play',
                'url' => $baseurl . '/decayingModel/enable/%id%',
                'requirement' => function ($row) use ($canEditRow) {
                    return $canEditRow($row) && empty($row['DecayingModel']['enabled']);
                },
            ],
            [
                'type' => 'postLink',
                'label' => __('Disable'),
                'icon' => 'pause',
                'url' => $baseurl . '/decayingModel/disable/%id%',
                'requirement' => function ($row) use ($canEditRow) {
                    return $canEditRow($row) && !empty($row['DecayingModel']['enabled']);
                },
            ],
            [
                'type' => 'divider',
                'requirement' => function ($row) use ($canEditRow) {
                    return $canEditRow($row) && empty($row['DecayingModel']['default']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/decayingModel/deleteSelection/%id%',
                'class' => 'text-danger',
                'size' => 'sm',
                'requirement' => function ($row) use ($canEditRow) {
                    return $canEditRow($row) && empty($row['DecayingModel']['default']);
                },
            ],
        ],
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $decayingModels,
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
                    [
                        'type' => 'button',
                        'label' => __('My models'),
                        'icon' => 'fas fa-user',
                        'class' => $scopeBtn($isMy),
                        'url' => $base . $sortSuffix . '/my_models:1',
                    ],
                    [
                        'type' => 'button',
                        'label' => __('Shared'),
                        'icon' => 'fas fa-share-nodes',
                        'class' => $scopeBtn($isShared),
                        'url' => $base . $sortSuffix . '/all_orgs:1',
                    ],
                    [
                        'type' => 'button',
                        'label' => __('Default'),
                        'icon' => 'fas fa-shield-halved',
                        'class' => $scopeBtn($isDefault),
                        'url' => $base . $sortSuffix . '/default_models:1',
                    ],
                ],
                'enable' => true,
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'DecayingModel.id',
            'row_dblclick_url' => $baseurl . '/decayingModel/view/%id%',
        ],
    ],
    'item_url' => '/decayingModel',
]);
