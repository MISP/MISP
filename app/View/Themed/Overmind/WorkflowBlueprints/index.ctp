<?php
// Header section
$headerTitle = __('Workflow Blueprints');
$headerDescription = __('Re-usable blocks of workflow logic that can be inserted into your workflows.');

$headerActions = [];

if ($this->Acl->canAccess('workflowBlueprints', 'update')) {
    $headerActions[] = [
        'type' => 'dropdown',
        'label' => __('Default blueprints'),
        'icon' => 'download',
        'class' => 'btn btn-outline-dark',
        'children' => [
            [
                'type' => 'navigate',
                'label' => __('Update from repository'),
                'icon' => 'rotate',
                'url' => '#',
                'class' => 'blueprint-update-trigger',
            ],
            ['type' => 'divider'],
            [
                'type' => 'navigate',
                'label' => __('Force update all'),
                'icon' => 'bolt',
                'url' => '#',
                'class' => 'blueprint-force-update-trigger',
            ],
        ],
    ];
}

if ($this->Acl->canAccess('workflowBlueprints', 'import')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Import workflow blueprint'),
        'icon' => 'file-import',
        'url' => $baseurl . '/workflowBlueprints/import'
    ];
}

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
        'url' => $baseurl . '/workflowBlueprints/view/%id%',
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
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'WorkflowBlueprint.name',
        'data_path' => 'WorkflowBlueprint.name, WorkflowBlueprint.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Default'),
        'sort' => 'WorkflowBlueprint.default',
        'data_path' => 'WorkflowBlueprint.default',
        'element' => 'default',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Timestamp'),
        'sort' => 'WorkflowBlueprint.timestamp',
        'data_path' => 'WorkflowBlueprint.timestamp',
        'element' => 'datetime',
        'card_section' => 'meta',
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

<?php if ($this->Acl->canAccess('workflowBlueprints', 'update')): ?>
    <div class="d-none">
        <?= $this->Form->postLink('', ['action' => 'update'], ['id' => 'blueprintUpdateLink']) ?>
        <?= $this->Form->postLink('', ['action' => 'update', true], ['id' => 'blueprintForceUpdateLink']) ?>
    </div>

    <script>
        (function () {
            function wire(triggerSelector, linkId, opts) {
                document.querySelectorAll(triggerSelector).forEach(function (el) {
                    el.addEventListener('click', function (e) {
                        e.preventDefault();
                        showConfirmModal(Object.assign({}, opts, {
                            onConfirm: function () {
                                document.getElementById(linkId).click();
                            }
                        }));
                    });
                });
            }

            wire('.blueprint-update-trigger', 'blueprintUpdateLink', {
                title: <?= json_encode(__('Update default blueprints')) ?>,
                body: <?= json_encode('<p class="mb-0">' . __('Pulls the default blueprints shipped with MISP and saves the ones that are newer than your copy. Blueprints you created are untouched.') . '</p>') ?>,
                confirmLabel: <?= json_encode(__('Update')) ?>,
                confirmClass: 'btn-primary'
            });

            wire('.blueprint-force-update-trigger', 'blueprintForceUpdateLink', {
                title: <?= json_encode(__('Force update default blueprints')) ?>,
                body: <?= json_encode(
                    '<p>' . __('Overwrites every default blueprint with the version from the repository, ignoring timestamps.') . '</p>'
                    . '<div class="alert alert-warning mb-0 py-2 small">'
                    . __('Any local change you made to a default blueprint will be lost. Blueprints you created yourself are not affected.')
                    . '</div>'
                ) ?>,
                confirmLabel: <?= json_encode(__('Force update')) ?>,
                confirmClass: 'btn-danger'
            });
        })();
    </script>
<?php endif; ?>
