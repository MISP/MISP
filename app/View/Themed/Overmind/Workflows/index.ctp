<?php
/*
 * Workflow hub.
 *
 * Three layers, top to bottom:
 *   1. four destination cards, one per workflow screen, colour-coded
 *   2. the workflow index itself (the list the legacy view showed on its own)
 *   3. the conceptual material — anatomy diagram + glossary — parked in a modal
 *      behind a header button, since it is read once and not on every visit
 *
 * The four accent colours label both the destination cards and the matching
 * blocks of the anatomy diagram, so the diagram doubles as a legend.
 */

$this->set('headerTitle', __('Workflows'));
$this->set('headerDescription', __('Automate MISP: one trigger fires, a graph of modules runs, actions are applied — or the operation is blocked.'));

$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('How workflows work'),
        'icon' => 'circle-question',
        'url' => '#',
        'onClick' => 'openWorkflowConcepts',
    ],
]);

$destinations = [
    'triggers' => [
        'accent' => 'auto',
        'icon' => 'bolt',
        'title' => __('Triggers'),
        'eyebrow' => __('Event-driven'),
        'value' => sprintf('%d / %d', $hubTriggers['enabled'], $hubTriggers['total']),
        'valueLabel' => __('enabled'),
        'body' => __('Core hooks MISP calls on its own — an event is published, an attribute is saved, a user logs in. Enable a hook here, then attach the workflow that should listen to it.'),
        'chips' => [
            ['icon' => 'project-diagram', 'text' => __('%s attached', $hubTriggers['attached'])],
            ['icon' => 'hand', 'text' => __('%s blocking', $hubTriggers['blocking'])],
            ['icon' => 'layer-group', 'text' => __n('%s scope', '%s scopes', $hubTriggers['scopes'], $hubTriggers['scopes'])],
        ],
        'url' => $baseurl . '/workflows/triggers',
        'cta' => __('Manage triggers'),
    ],
    'adhoc' => [
        'accent' => 'manual',
        'icon' => 'hand-pointer',
        'title' => __('Ad-hoc workflows'),
        'eyebrow' => __('Manual'),
        'value' => sprintf('%d / %d', $hubAdhoc['enabled'], $hubAdhoc['total']),
        'valueLabel' => __('enabled'),
        'body' => __('Workflows with no core hook: you run them yourself. Their synthetic trigger holds the data to feed in — a RestSearch query, passed event IDs, or the roaming data of a calling workflow.'),
        'chips' => [
            ['icon' => 'play-circle', 'text' => __('Run on demand')],
            ['icon' => 'sitemap', 'text' => __('Callable from other workflows')],
        ],
        'url' => $baseurl . '/workflows/adhoc',
        'cta' => __('Manage ad-hoc workflows'),
    ],
    'modules' => [
        'accent' => 'module',
        'icon' => 'shapes',
        'title' => __('Modules'),
        'eyebrow' => __('Building blocks'),
        'value' => sprintf('%d / %d', $hubModules['enabled'], $hubModules['total']),
        'valueLabel' => __('enabled'),
        'body' => __('The catalogue the editor draws from. Logic modules branch and filter the execution path; action modules do the work. A disabled module does not appear on the canvas at all.'),
        'chips' => [
            ['icon' => 'cog', 'text' => __('%s action', $hubModules['action'])],
            ['icon' => 'code-branch', 'text' => __('%s logic', $hubModules['logic'])],
            ['icon' => 'plug', 'text' => __('%s via misp-modules', $hubModules['misp_module'])],
        ],
        'url' => $baseurl . '/workflows/moduleIndex',
        'cta' => __('Manage modules'),
    ],
    'blueprints' => [
        'accent' => 'blueprint',
        'icon' => 'puzzle-piece',
        'title' => __('Blueprints'),
        'eyebrow' => __('Reusable fragments'),
        'value' => (string)$hubBlueprints['total'],
        'valueLabel' => __n('blueprint', 'blueprints', $hubBlueprints['total']),
        'body' => __('Saved chunks of graph — nodes plus their connections, no trigger. Multi-select in the editor to save one, then drag it into any workflow. Inserting copies the nodes, so later edits to the blueprint do not propagate.'),
        'chips' => [
            ['icon' => 'download', 'text' => __('%s shipped by default', $hubBlueprints['default'])],
            ['icon' => 'file-import', 'text' => __('Import / export as JSON')],
        ],
        'url' => $baseurl . '/workflowBlueprints/index',
        'cta' => __('Manage blueprints'),
    ],
];

$moduleWarnings = [];
if (!empty($hubModules['service_error'])) {
    $moduleWarnings[] = __('misp-modules action service unreachable');
}
if (!empty($hubModules['loading_errors'])) {
    $moduleWarnings[] = __n('%s module failed to load', '%s modules failed to load', $hubModules['loading_errors'], $hubModules['loading_errors']);
}

$concepts = [
    [
        'icon' => 'hand',
        'title' => __('Blocking vs non-blocking'),
        'body' => [
            __('A blocking workflow can cancel the MISP operation that called it; a non-blocking one runs after the fact and cannot.'),
            __('Example: an event gets published, the blocking `publish` trigger fires, and a blocking module such as `stop-execution` prevents the publication.'),
            __('Blocking modules placed in a non-blocking workflow have no blocking effect.'),
        ],
    ],
    [
        'icon' => 'file-code',
        'title' => __('MISP core format'),
        'body' => [
            __('The standardised shape of the data travelling from module to module. Triggers and modules advertise whether they speak it, so a mismatch is visible before you run anything.'),
            __('Attributes live under `Event.Attribute`, or under `Event._AttributeFlattened` to include object attributes.'),
        ],
    ],
    [
        'icon' => 'random',
        'title' => __('Concurrent task'),
        'body' => [
            __('A logic module that breaks the execution path off into a background task.'),
            __('Everything after it runs later in a worker, which also means a blocking module placed after it can no longer cancel the ongoing operation.'),
        ],
    ],
    [
        'icon' => 'bug',
        'title' => __('Debugging a workflow'),
        'body' => [
            __('Executions are logged in the application logs and in `app/tmp/logs/workflow-execution.log`.'),
            __('Turning debug mode on a workflow makes every node POST its data to `Plugin.Workflow_debug_url`.'),
        ],
    ],
];

$workflowFields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Workflow.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Workflow.id',
        'data_path' => 'Workflow.id',
        'element' => 'id',
        //'url' => $baseurl . '/workflows/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('UUID'),
        'sort' => 'Workflow.uuid',
        'data_path' => 'Workflow.uuid',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Name'),
        'sort' => 'Workflow.name',
        'data_path' => 'Workflow.name, Workflow.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Listening triggers'),
        'data_path' => 'Workflow.listening_triggers',
        'element' => 'custom',
        'function' => function ($row) use ($baseurl) {
            $triggers = Hash::get($row, 'Workflow.listening_triggers');
            if (empty($triggers) || !is_array($triggers)) {
                return sprintf('<span class="text-muted small">%s</span>', __('none'));
            }
            $chips = '';
            foreach ($triggers as $trigger) {
                $disabled = !empty($trigger['disabled']);
                $isAdhoc = !empty($trigger['is_adhoc'])
                    || strpos((string)$trigger['id'], 'adhoc_') === 0;
                $title = $disabled
                    ? __('Trigger disabled')
                    : ($isAdhoc ? __('Ad-hoc trigger — run manually') : ($trigger['name'] ?? $trigger['id']));
                $chips .= sprintf(
                    '<a class="wf-chip wf-chip-%s text-decoration-none%s" href="%s/workflows/moduleView/%s" title="%s">'
                        . '<i class="fa-fw %s"></i>%s</a>',
                    $isAdhoc ? 'manual' : 'auto',
                    $disabled ? ' opacity-50 text-decoration-line-through' : '',
                    h($baseurl),
                    h($trigger['id']),
                    h($title),
                    $this->FontAwesome->getClass($trigger['icon'] ?? 'flag'),
                    h($trigger['id'])
                );
            }
            return '<div class="d-flex flex-wrap gap-1">' . $chips . '</div>';
        },
        'card_section' => 'tag',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Run counter'),
        'sort' => 'Workflow.counter',
        'data_path' => 'Workflow.counter',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Debug enabled'),
        'sort' => 'Workflow.debug_enabled',
        'data_path' => 'Workflow.debug_enabled',
        'element' => 'debug_enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Last update'),
        'sort' => 'Workflow.timestamp',
        'data_path' => 'Workflow.timestamp',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Workflow.id',
        'card_section' => 'extra',
        'actions' => array_values(array_filter([
            [
                'type' => 'navigate',
                'label' => __('Open in editor'),
                'icon' => 'code',
                'url' => $baseurl . '/workflows/editor/%id%',
            ],
            // [
            //     'type' => 'navigate',
            //     'label' => __('View'),
            //     'icon' => 'eye',
            //     'url' => $baseurl . '/workflows/view/%id%',
            // ],
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/workflows/edit/%id%',
            ] : null,
            [
                'type' => 'navigate',
                'label' => __('Execution logs'),
                'icon' => 'rectangle-list',
                'url' => $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow/model_id:%id%',
            ],
            $isSiteAdmin ? [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/workflows/deleteSelection/%id%',
                'class' => 'text-danger',
            ] : null,
        ])),
    ],
];

$workflowFilterBar = [
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
if ($isSiteAdmin) {
    $workflowFilterBar['delete'] = '/deleteSelection';
}
?>


<!-- ===================== WORKFLOW CARDS ===================== -->
<div class="wf-scope container-fluid mb-4">
    <div class="d-flex flex-wrap align-items-baseline gap-2 mb-2">
        <h2 class="h6 fw-bold mb-0"><?= __('Where to go') ?></h2>
        <span class="text-muted" style="font-size:.8rem;">
            <?= __('Here are the various components that make up a workflow.') ?>
        </span>
        <span class="wf-meta ms-auto d-flex flex-wrap gap-3">
            <span><i class="fas fa-rotate fa-fw me-1"></i><?= __('%s executions so far', sprintf('<strong>%d</strong>', $hubWorkflows['runs'])) ?></span>
            <?php if (!empty($hubWorkflows['debugging'])): ?>
                <span class="text-warning-emphasis">
                    <i class="fas fa-bug fa-fw me-1"></i>
                    <?= __n('%s workflow in debug mode', '%s workflows in debug mode', $hubWorkflows['debugging'], sprintf('<strong>%d</strong>', $hubWorkflows['debugging'])) ?>
                </span>
            <?php endif; ?>
        </span>
    </div>

    <div class="row g-3">
        <?php foreach ($destinations as $key => $dest): ?>
            <div class="col-12 col-md-6 col-xxl-3">
                <div class="card shadow-sm wf-dest wf-accent-<?= h($dest['accent']) ?>">
                    <div class="card-body p-3 d-flex flex-column">

                        <div class="d-flex align-items-start gap-3 mb-3">
                            <span class="wf-dest-icon"><i class="fas fa-<?= h($dest['icon']) ?>"></i></span>
                            <div class="flex-grow-1" style="min-width:0;">
                                <div class="wf-dest-eyebrow"><?= h($dest['eyebrow']) ?></div>
                                <div class="fw-bold" style="font-size:1rem;"><?= h($dest['title']) ?></div>
                            </div>
                        </div>

                        <div class="d-flex align-items-baseline gap-2 mb-2">
                            <span class="wf-dest-value"><?= h($dest['value']) ?></span>
                            <span class="text-muted" style="font-size:.75rem;"><?= h($dest['valueLabel']) ?></span>
                        </div>

                        <div class="d-flex flex-wrap gap-1 mb-3">
                            <?php foreach ($dest['chips'] as $chip): ?>
                                <span class="wf-chip">
                                    <i class="fas fa-<?= h($chip['icon']) ?>"></i><?= h($chip['text']) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>

                        <p class="text-muted mb-3" style="font-size:.8rem; line-height:1.45;">
                            <?= h($dest['body']) ?>
                        </p>

                        <?php if ($key === 'modules' && !empty($moduleWarnings)): ?>
                            <div class="alert alert-warning py-2 px-2 mb-3" style="font-size:.75rem;">
                                <?php foreach ($moduleWarnings as $warning): ?>
                                    <div><i class="fas fa-triangle-exclamation fa-fw me-1"></i><?= h($warning) ?></div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>

                        <a href="<?= h($dest['url']) ?>"
                           class="wf-dest-cta stretched-link text-decoration-none mt-auto d-inline-flex align-items-center gap-1">
                            <?= h($dest['cta']) ?><i class="fas fa-arrow-right" style="font-size:.7rem;"></i>
                        </a>

                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

</div>

<!-- ===================== WORKFLOW INDEX ===================== -->
<?php
// Rendered outside the block above so the scaffold's own .container-fluid lines
// its cards up with the destination cards instead of nesting the gutters.
echo '<div class="wf-scope">';
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => $workflowFilterBar,
            'fields' => $workflowFields,
        ]
    ],
    'item_url' => '/workflows'
]);
echo '</div>';
?>

<!-- ===================== CONCEPTS MODAL ===================== -->
<div class="modal fade wf-scope" id="wf-concepts-modal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">

            <div class="modal-header">
                <h5 class="modal-title fw-bold"><?= __('How workflows work') ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
            </div>

            <div class="modal-body">

                <div class="d-flex flex-wrap align-items-baseline gap-2 mb-3">
                    <h6 class="fw-bold mb-0"><?= __('Anatomy of a workflow') ?></h6>
                    <span class="text-muted" style="font-size:.8rem;">
                        <?= __('Every workflow — automatic or manual — has this same shape.') ?>
                    </span>
                </div>

                <div class="wf-flow mb-4">

                    <!-- 1. trigger -->
                    <div class="wf-lane">
                        <div class="wf-lane-head">
                            <span class="wf-step">1</span>
                            <span class="wf-lane-title"><?= __('Trigger') ?></span>
                            <span class="wf-cardinality" title="<?= __('A workflow is attached to exactly one trigger') ?>"><?= __('exactly 1') ?></span>
                        </div>
                        <div class="wf-node wf-accent-auto">
                            <i class="fas fa-bolt fa-fw"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Core hook') ?></div>
                                <div class="wf-node-sub"><?= __('MISP fires it: event published, attribute saved, user created…') ?></div>
                            </div>
                        </div>
                        <div class="wf-or"><?= __('or') ?></div>
                        <div class="wf-node wf-accent-manual">
                            <i class="fas fa-hand-pointer fa-fw"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Ad-hoc trigger') ?></div>
                                <div class="wf-node-sub"><?= __('You fire it, and it declares which data to load.') ?></div>
                            </div>
                        </div>
                    </div>

                    <div class="wf-link"><i class="fas fa-chevron-right"></i></div>

                    <!-- 2. graph -->
                    <div class="wf-lane">
                        <div class="wf-lane-head">
                            <span class="wf-step">2</span>
                            <span class="wf-lane-title"><?= __('Graph of modules') ?></span>
                            <span class="wf-cardinality" title="<?= __('A workflow may chain any number of modules') ?>"><?= __('0 to n') ?></span>
                        </div>
                        <div class="wf-node wf-accent-blueprint wf-node-dashed wf-feeds">
                            <i class="fas fa-puzzle-piece fa-fw"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Blueprint') ?></div>
                                <div class="wf-node-sub"><?= __('A saved fragment, copied into the graph below.') ?></div>
                            </div>
                        </div>
                        <div class="wf-node wf-accent-module">
                            <i class="fas fa-code-branch fa-fw"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Logic module') ?></div>
                                <div class="wf-node-sub"><?= __('Conditions and filters that split the execution path.') ?></div>
                            </div>
                        </div>
                        <div class="wf-node wf-accent-module">
                            <i class="fas fa-cog fa-fw"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Action module') ?></div>
                                <div class="wf-node-sub"><?= __('Tag, publish, enrich, webhook, mail, stop execution…') ?></div>
                            </div>
                        </div>
                    </div>

                    <div class="wf-link"><i class="fas fa-chevron-right"></i></div>

                    <!-- 3. outcome -->
                    <div class="wf-lane">
                        <div class="wf-lane-head">
                            <span class="wf-step">3</span>
                            <span class="wf-lane-title"><?= __('Outcome') ?></span>
                            <span class="wf-cardinality"><?= __('per path') ?></span>
                        </div>
                        <div class="wf-node wf-node-neutral">
                            <i class="fas fa-check-circle fa-fw text-success"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Actions applied') ?></div>
                                <div class="wf-node-sub"><?= __('The MISP operation proceeds as usual.') ?></div>
                            </div>
                        </div>
                        <div class="wf-or"><?= __('or') ?></div>
                        <div class="wf-node wf-node-neutral">
                            <i class="fas fa-ban fa-fw text-danger"></i>
                            <div>
                                <div class="wf-node-title"><?= __('Operation blocked') ?></div>
                                <div class="wf-node-sub"><?= __('Only when a blocking trigger meets a blocking module.') ?></div>
                            </div>
                        </div>
                    </div>

                </div>

                <h6 class="fw-bold mb-2"><?= __('Key concepts') ?></h6>
                <div class="accordion" id="wf-concepts">
                    <?php foreach ($concepts as $i => $concept): ?>
                        <div class="accordion-item">
                            <h3 class="accordion-header">
                                <button class="accordion-button collapsed" type="button"
                                        data-bs-toggle="collapse" data-bs-target="#wf-concept-<?= (int)$i ?>">
                                    <i class="fas fa-<?= h($concept['icon']) ?> fa-fw me-2 text-secondary"></i>
                                    <?= h($concept['title']) ?>
                                </button>
                            </h3>
                            <div id="wf-concept-<?= (int)$i ?>" class="accordion-collapse collapse" data-bs-parent="#wf-concepts">
                                <div class="accordion-body pt-0" style="font-size:.83rem; line-height:1.55;">
                                    <?php foreach ($concept['body'] as $paragraph): ?>
                                        <p class="text-muted mb-2"><?= h($paragraph) ?></p>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

            </div>
        </div>
    </div>
</div>

<script>
    function openWorkflowConcepts() {
        var el = document.getElementById('wf-concepts-modal');
        if (el && window.bootstrap) {
            bootstrap.Modal.getOrCreateInstance(el).show();
        }
    }
</script>
