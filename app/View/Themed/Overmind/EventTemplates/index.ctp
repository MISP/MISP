<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('Event Templates');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('eventTemplates', 'update')) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Update from library'),
        'icon' => 'sync',
        // headerSection.ctp's onClick wiring fires
        // `event.preventDefault(); FUNC();` so the href is never followed —
        // the popover loads via getPopup into #popover_form. The url is
        // kept as a no-script fallback / right-click target.
        'url' => $baseurl . '/event_templates/update',
        'onClick' => 'openEventTemplateLibraryUpdatePopup',
    ];
}

if ($this->Acl->canAccess('eventTemplates', 'import')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Import Template'),
        'icon' => 'file-import',
        'url' => $baseurl . '/event_templates/import',
    ];
}

if ($this->Acl->canAccess('eventTemplates', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Event Template'),
        'icon' => 'plus',
        'url' => $baseurl . '/event_templates/add',
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'EventTemplate.id',
        'card_section' => 'selector',
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
        'name' => __('UUID'),
        'sort' => 'EventTemplate.uuid',
        'data_path' => 'EventTemplate.uuid',
        'element' => 'uuid',
        'url' => $baseurl . '/event_templates/view/%id%',
        'card_section' => 'top',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Name'),
        'sort' => 'EventTemplate.name',
        'data_path' => 'EventTemplate',
        'element' => 'event_template_name',
        'url' => $baseurl . '/event_templates/view/%id%',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Distribution'),
        'sort' => 'EventTemplate.distribution',
        'data_path' => 'EventTemplate.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card'],
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
        'name' => __('Active'),
        'sort' => 'EventTemplate.active',
        'data_path' => 'EventTemplate.active',
        'element' => 'active',
        'title_off' => __('Inactive templates are hidden from the "From template" picker'),
        'card_section' => 'top',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Version'),
        'sort' => 'EventTemplate.version',
        'data_path' => 'EventTemplate.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Source'),
        'sort' => 'EventTemplate.misp_default',
        'data_path' => 'EventTemplate.misp_default',
        'element' => 'library_managed',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Sections'),
        'data_path' => 'EventTemplate.definition.structure',
        'element' => 'event_template_element_count',
        'count_type' => 'section',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Elements'),
        'data_path' => 'EventTemplate.definition.structure',
        'element' => 'event_template_element_count',
        'count_type' => 'non_section',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Modified'),
        'sort' => 'EventTemplate.modified',
        'data_path' => 'EventTemplate.modified',
        'element' => 'datetime',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'EventTemplate.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/event_templates/view/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Create event from template'),
                'icon' => 'play',
                'url' => $baseurl . '/event_templates/instantiate/%id%',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'instantiate'),
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/event_templates/edit/%id%',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'edit'),
            ],
            [
                // GET renders the confirmation modal, POST duplicates.
                'type' => 'modal',
                'label' => __('Duplicate'),
                'icon' => 'copy',
                'url' => $baseurl . '/event_templates/duplicate/%id%',
                'size' => 'md',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'duplicate'),
            ],
            [
                'type' => 'navigate',
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
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/event_templates/deleteSelection/%id%',
                'size' => 'md',
                'class' => 'text-danger',
                'requirement' => $this->Acl->canAccess('eventTemplates', 'delete'),
            ],
        ],
    ],
];


// Genuine empty state vs filtered-with-no-hits. See default-theme index for
// the rationale — let IndexTable's standard "no matching records" handle the
// latter so we don't misled a user who typed in the search box.
$indexFilters = isset($this->request->params['named']) ? $this->request->params['named'] : array();
$indexQuery = isset($this->request->query) ? $this->request->query : array();
$filterActive = !empty($indexFilters) || !empty($indexQuery);
if (empty($list) && !$filterActive) {
    $canAdd = $this->Acl->canAccess('eventTemplates', 'add');
    $canImport = $this->Acl->canAccess('eventTemplates', 'import');
    ?>
    <div class="container-fluid mt-4">
        <div class="card border-0 shadow-sm">
            <div class="card-body text-center py-5">
                <div class="mb-3 text-primary" style="font-size:3rem;">
                    <i class="fas fa-clipboard-list"></i>
                </div>
                <h4 class="mb-2"><?= __('No event templates yet') ?></h4>
                <p class="text-muted mb-4 mx-auto" style="max-width:560px;">
                    <?= __('Event templates let your team scaffold a consistent event for a '
                        . 'recurring incident type — the creator authors the structure once '
                        . '(sections, attribute fields, MISP objects, tags, galaxies), and '
                        . 'other users fill in just the values for each new event.') ?>
                </p>
                <div class="d-flex gap-2 justify-content-center">
                    <?php if ($canAdd): ?>
                        <a href="<?= h($baseurl . '/event_templates/add') ?>"
                           class="btn btn-primary"
                           onclick="event.preventDefault(); openModal('<?= h($baseurl . '/event_templates/add') ?>');">
                            <i class="fas fa-plus me-1"></i>
                            <?= __('Add your first template') ?>
                        </a>
                    <?php endif; ?>
                    <?php if ($canImport): ?>
                        <a href="<?= h($baseurl . '/event_templates/import') ?>"
                           class="btn btn-outline-secondary"
                           onclick="event.preventDefault(); openModal('<?= h($baseurl . '/event_templates/import') ?>');">
                            <i class="fas fa-upload me-1"></i>
                            <?= __('Import from JSON') ?>
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <?php
    return;
}

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
                'delete' => $this->Acl->canAccess('eventTemplates', 'delete')
                    ? '/deleteSelection'
                    : null,
            ],
            'fields' => $fields,
            'primary_id_path' => 'EventTemplate.id',
            'row_dblclick_url' => $baseurl . '/event_templates/view/%id%',
        ],
    ],
    'item_url' => '/event_templates',
]);
