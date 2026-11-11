<?php
/*
 * Workflow editor — Bootstrap 5 markup.
 *
 * Every id and class below is load-bearing — the editor script looks them up by
 * name. Do not rename without grepping workflows-editor.js first:
 *   .root-container .side-panel .canvas #loadingBackdrop #drawflow
 *   #block-tabs a[href="#container-…"]  .tab-pane#container-{actions,logic,blueprints}
 *   #block-filter-group button[data-type]  select.chosen-container.blocks(.blueprint-select)
 *   .block-container  .sidebar-minimize-button  .sidebar-maximize-button
 *   #saveWorkflow #workflow-saved-container #workflow-saved-text
 *   #workflow-saved-text-details #workflow-debug-button b.state-text
 *   #workflow-run-button #saveBlueprint
 *   .control-buttons #control-{duplicate,frame-node,delete,save-blocks,
 *                              import-blocks,import-blocks-container}
 *   .control-edit-bp-blocks
 *   #block-modal (+ #delete-selected-node) #block-notifications-modal
 *   #block-filtering-modal — each needs a .modal-body, which the script empties
 *   and refills.
 *
 * The Bootstrap 2 jQuery plugin calls the script makes (.modal(), .tab(),
 * .popover(), the `show`/`shown` events and `data-toggle="modal"`) are bridged
 * onto Bootstrap 5 by workflows-editor-bs5-compat.js.
 */

$usableModules = [
    'modules_action' => $modules['modules_action'],
    'modules_logic' => $modules['modules_logic'],
];
$allModules = array_merge($usableModules['modules_action'], $usableModules['modules_logic']);
$triggerModules = $modules['modules_trigger'];
$selectedTrigger = Hash::get($selectedWorkflow, 'Workflow.listening_triggers.0', []);
$isBlockingTrigger = $selectedTrigger['blocking'] ?? false;
$isMISPFormat = $selectedTrigger['misp_core_format'] ?? false;
$debugEnabled = !empty($selectedWorkflow['Workflow']['debug_enabled']);

// The editor supplies its own topbar; the theme's header strip would only eat
// vertical space the canvas needs.
$this->set('hideHeaderSection', true);
?>
<div class="root-container">
    <div class="topbar px-3">
        <?php if (!empty($selectedTrigger['is_adhoc'])): ?>
            <a class="text-decoration-none d-inline-flex align-items-center gap-1" href="<?= $baseurl . '/workflows/adhoc' ?>">
                <i class="fa-fw <?= $this->FontAwesome->getClass('caret-left') ?>"></i><?= __('Ad-Hoc index') ?>
            </a>
        <?php else: ?>
            <a class="text-decoration-none d-inline-flex align-items-center gap-1" href="<?= $baseurl . '/workflows/triggers' ?>">
                <i class="fa-fw <?= $this->FontAwesome->getClass('caret-left') ?>"></i><?= __('Trigger index') ?>
            </a>
        <?php endif; ?>

        <span class="d-flex align-items-center gap-2" style="min-width: 220px;">
            <h3 class="d-inline-block mb-0 fs-5">
                <span class="fw-normal"><?= __('Workflow:') ?></span>
                <strong><?= h($selectedWorkflow['Workflow']['trigger_id']) ?></strong>
                <?php if (!empty($selectedTrigger['is_adhoc'])): ?>
                    - <span class="me-3"><?= h($selectedWorkflow['Workflow']['name']) ?></span>
                <?php endif; ?>
            </h3>
            <?php if (!empty($isBlockingTrigger)) : ?>
                <span class="badge text-bg-danger d-inline-flex align-items-center gap-1" title="<?= __('This workflow is a blocking workflow and can prevent the default MISP behavior to execute') ?>">
                    <i class="fa-fw <?= $this->FontAwesome->getClass('stop-circle') ?>"></i>
                    <?= __('Blocking') ?>
                </span>
            <?php else : ?>
                <span class="badge text-bg-success d-inline-flex align-items-center gap-1" title="<?= __('This workflow is a not blocking workflow. The default MISP behavior will or has already happened') ?>">
                    <i class="fa-fw <?= $this->FontAwesome->getClass('check-circle') ?>"></i>
                    <?= __('Non blocking') ?>
                </span>
            <?php endif; ?>
            <?php if (!empty($isMISPFormat)) : ?>
                <span class="badge d-inline-flex align-items-center" style="background-color: #009fdc;" title="<?= __('The data passed by this trigger is compliant with the MISP core format') ?>">
                    <img src="<?= $baseurl ?>/img/misp-logo-no-text.png" alt="MISP Core format" width="18" height="18" style="filter: brightness(0) invert(1);">
                </span>
            <?php endif; ?>
        </span>

        <span class="d-flex align-items-center">
            <button id="saveWorkflow" class="btn btn-primary btn-sm d-inline-flex align-items-center gap-1" type="button">
                <i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?>
                <span class="fa fa-spin fa-spinner loading-span d-none"></span>
            </button>
            <span id="workflow-saved-container" class="fa-stack ms-2">
                <i class="<?= $this->FontAwesome->getClass('cloud') ?> fa-stack-2x"></i>
                <i class="<?= $this->FontAwesome->getClass('save') ?> fa-stack-1x fa-inverse" style="top: 0.15em;"></i>
            </span>
            <span id="workflow-saved-text" class="ms-1"></span>
            <span id="workflow-saved-text-details" class="ms-1" style="font-size: 0.75em"></span>
        </span>

        <span class="d-flex align-items-center ms-auto me-3 gap-3">
            <button id="workflow-debug-button" type="button"
                    class="btn btn-sm btn-<?= $debugEnabled ? 'success' : 'primary' ?> d-inline-flex align-items-center gap-1"
                    data-enabled="<?= $debugEnabled ? '1' : '0' ?>">
                <i class="<?= $this->FontAwesome->getClass('bug') ?> fa-fw"></i>
                <?= __('Debug Mode: ') ?>
                <b class="state-text" data-on="<?= __('On') ?>" data-off="<?= __('Off') ?>"><?= $debugEnabled ? __('On') : __('Off') ?></b>
            </button>
            <button id="workflow-run-button" type="button" class="btn btn-sm btn-primary d-inline-flex align-items-center gap-1" <?= $debugEnabled ? '' : 'disabled' ?>>
                <i class="<?= $this->FontAwesome->getClass('play') ?> fa-fw"></i>
                <?= __('Run Workflow') ?>
            </button>
            <a class="text-decoration-none d-inline-flex align-items-center gap-1"
               href="<?= $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow/model_id:' . h($selectedWorkflow['Workflow']['id']) ?>"
               title="<?= __('View execution logs') ?>" aria-label="<?= __('View execution logs') ?>">
                <i class="<?= $this->FontAwesome->getClass('list-alt') ?>"></i> <?= __('Execution logs') ?>
            </a>
            <button class="btn btn-info btn-sm" type="button" data-bs-toggle="modal" data-bs-target="#workflow-info-modal" title="<?= __('View help') ?>">
                <i class="<?= $this->FontAwesome->getClass('info-circle') ?>"></i>
            </button>
        </span>
    </div>

    <div class="main-container">
        <div class="sidebar">
            <div class="side-panel bg-body">
                <span class="sidebar-minimize-button">
                    <i class="<?= $this->FontAwesome->getClass('angle-double-left') ?>"></i>
                </span>
                <span class="sidebar-maximize-button">
                    <i class="<?= $this->FontAwesome->getClass('angle-double-right') ?>"></i>
                </span>

                <ul class="nav nav-tabs" id="block-tabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <a class="nav-link active" href="#container-actions" role="tab">
                            <i class="<?= $this->FontAwesome->getClass('play') ?>"></i>
                            <?= __('Actions') ?>
                        </a>
                    </li>
                    <li class="nav-item" role="presentation">
                        <a class="nav-link" href="#container-logic" role="tab">
                            <i class="<?= $this->FontAwesome->getClass('code-branch') ?>"></i>
                            <?= __('Logic') ?>
                        </a>
                    </li>
                    <li class="nav-item" role="presentation">
                        <a class="nav-link" href="#container-blueprints" role="tab">
                            <i class="<?= $this->FontAwesome->getClass('shapes') ?>"></i>
                            <?= __('Blueprints') ?>
                        </a>
                    </li>
                </ul>

                <div class="tab-content">
                    <div class="tab-pane active" id="container-actions" role="tabpanel">
                        <div id="block-filter-group" class="btn-group btn-group-sm m-2" role="group">
                            <button type="button" class="btn btn-primary active" data-type="enabled" onclick="filterModules(this)"><?= __('Enabled') ?></button>
                            <button type="button" class="btn btn-primary" data-type="misp-module" onclick="filterModules(this)">
                                misp-module<span class="is-misp-module"></span>
                            </button>
                            <button type="button" class="btn btn-primary" data-type="is-blocking" onclick="filterModules(this)">
                                <?= __('Blocking') ?>
                            </button>
                            <button type="button" class="btn btn-primary" data-type="all" onclick="filterModules(this)"><?= __('All') ?></button>
                        </div>
                        <select type="text" placeholder="<?= __('Search for a block') ?>" class="chosen-container blocks" autocomplete="off">
                            <?php foreach ($modules['modules_action'] as $block) : ?>
                                <?php if (empty($block['disabled'])) : ?>
                                    <option value="<?= h($block['id']) ?>"><?= h($block['name']) ?></option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                        <div class="block-container">
                            <?php foreach ($modules['modules_action'] as $block) : ?>
                                <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                            <?php endforeach; ?>
                            <?php if (empty($modules['modules_action'])) : ?>
                                <div class="alert alert-danger m-2">
                                    <?= __('There are no modules available. They can be enabled %s.', sprintf('<a href="%s">%s</a>', $baseurl . '/workflows/moduleIndex', __('here'))) ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="tab-pane" id="container-logic" role="tabpanel">
                        <select type="text" placeholder="<?= __('Search for a block') ?>" class="chosen-container blocks" autocomplete="off" style="width: 305px; margin: 0 0.5em;">
                            <?php foreach ($modules['modules_logic'] as $block) : ?>
                                <?php if (empty($block['disabled'])) : ?>
                                    <option value="<?= h($block['id']) ?>"><?= h($block['name']) ?></option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                        <div class="block-container">
                            <?php foreach ($modules['modules_logic'] as $block) : ?>
                                <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                            <?php endforeach; ?>
                        </div>
                        <?php if (empty($modules['modules_logic'])) : ?>
                            <div class="alert alert-danger mt-2">
                                <?= __('There are no modules available. They can be enabled %s.', sprintf('<a href="%s">%s</a>', $baseurl . '/workflows/moduleIndex/type:logic', __('here'))) ?>
                            </div>
                        <?php endif; ?>
                    </div>

                    <div class="tab-pane" id="container-blueprints" role="tabpanel">
                        <div class="ms-2 mb-2">
                            <a id="saveBlueprint" class="btn btn-primary btn-sm d-inline-flex align-items-center gap-1" href="<?= $baseurl . '/workflowBlueprints/add/1' ?>">
                                <i class="<?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save blueprint') ?>
                            </a>
                        </div>
                        <select type="text" placeholder="<?= __('Search for a block') ?>" class="chosen-container blocks blueprint-select" autocomplete="off" style="width: 305px; margin: 0 0.5em;">
                            <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                <option value="<?= h($workflowBlueprint['WorkflowBlueprint']['id']) ?>"><?= h($workflowBlueprint['WorkflowBlueprint']['name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="block-container">
                            <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                <?= $this->element('Workflows/sidebar-block-workflow-blueprint', ['workflowBlueprint' => $workflowBlueprint['WorkflowBlueprint']]) ?>
                            <?php endforeach; ?>
                            <?php if (empty($workflowBlueprints)) : ?>
                                <div class="alert alert-info mt-2">
                                    <?= __('There are no blueprint available. You can create some by multi-selecting nodes and then saving the blueprint.') ?>
                                    <?= __('Alternatively, Blueprints can be imported on the %s', sprintf('<a href="%s">%s</a>', $baseurl . '/workflowBlueprints/index', __('blueprint index'))) ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="rightbar">
            <div class="right-panel">
                <div class="btn-group btn-group-sm control-buttons">
                    <button id="control-duplicate" class="btn btn-primary disabled" type="button" title="<?= __('Duplicate') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('clone') ?>"></i> <?= __('Duplicate') ?>
                    </button>
                    <button id="control-frame-node" class="btn btn-primary disabled" type="button" title="<?= __('Create frame node') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('object-group') ?>"></i> <?= __('Frame') ?>
                    </button>
                    <button id="control-delete" class="btn btn-danger disabled" type="button" title="<?= __('Delete') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('trash') ?>"></i> <?= __('Delete') ?>
                    </button>
                    <button class="btn btn-primary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('shapes') ?>"></i> <?= __('Blueprints') ?>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li id="control-import-blocks" class="dropdown-submenu">
                            <a class="dropdown-item" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-import') ?>"></i> <?= __('Import blueprint') ?></a>
                            <ul class="dropdown-menu">
                                <?php if (empty($workflowBlueprints)) : ?>
                                    <li><a class="dropdown-item" href="#"><?= __('No workflow blueprints saved') ?></a></li>
                                <?php endif; ?>
                                <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                    <li>
                                        <a class="dropdown-item" href="#" title="<?= h($workflowBlueprint['WorkflowBlueprint']['description']) ?>" onclick="addWorkflowBlueprint(<?= h($workflowBlueprint['WorkflowBlueprint']['id']) ?>)">
                                            <?= h($workflowBlueprint['WorkflowBlueprint']['name']) ?>
                                            <small class="text-muted">[<?= h(substr($workflowBlueprint['WorkflowBlueprint']['uuid'], 0, 4)) ?>...]</small>
                                        </a>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </li>
                        <li id="control-save-blocks" class="disabled">
                            <a class="dropdown-item" href="<?= $baseurl . '/workflowBlueprints/add/1' ?>"><i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save blueprint') ?></a>
                        </li>
                        <li id="control-import-blocks-container" class="dropdown-submenu disabled">
                            <a class="dropdown-item" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('edit') ?>"></i> <?= __('Edit existing blueprint') ?></a>
                            <ul class="dropdown-menu disabled">
                                <?php if (empty($workflowBlueprints)) : ?>
                                    <li><a class="dropdown-item" href="#"><?= __('No workflow blueprints saved') ?></a></li>
                                <?php endif; ?>
                                <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                    <li class="control-edit-bp-blocks">
                                        <a class="dropdown-item" href="<?= $baseurl . '/workflowBlueprints/edit/' . h($workflowBlueprint['WorkflowBlueprint']['id']) ?>" title="<?= h($workflowBlueprint['WorkflowBlueprint']['description']) ?>" data-bp-id="<?= h($workflowBlueprint['WorkflowBlueprint']['id']) ?>">
                                            <?= h($workflowBlueprint['WorkflowBlueprint']['name']) ?>
                                            <small class="text-muted">[<?= h(substr($workflowBlueprint['WorkflowBlueprint']['uuid'], 0, 4)) ?>...]</small>
                                        </a>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="canvas">
            <div id="drawflow" data-workflowid="<?= h($selectedWorkflow['Workflow']['id']) ?>"></div>
            <div id="loadingBackdrop" class="modal-backdrop" style="display: none;"></div>
        </div>
    </div>
</div>

<?php
/*
 * The three node modals. The script empties and refills `.modal-body`, so that
 * class must stay; everything around it is Bootstrap 5's dialog/content
 * structure. `#block-modal` additionally needs `#delete-selected-node`.
 */
?>
<div id="block-modal" class="modal fade" tabindex="-1" aria-labelledby="block-modal-label" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title fw-bold" id="block-modal-label"><?= __('Node settings') ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <p><?= __('Node settings') ?></p>
            </div>
            <div class="modal-footer justify-content-between">
                <button id="delete-selected-node" type="button" class="btn btn-danger"><?= __('Delete node') ?></button>
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Close') ?></button>
            </div>
        </div>
    </div>
</div>

<div id="block-notifications-modal" class="modal fade" tabindex="-1" aria-labelledby="block-notifications-modal-label" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title fw-bold" id="block-notifications-modal-label"><?= __('Node Notifications') ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <p><?= __('Node notifications') ?></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Close') ?></button>
            </div>
        </div>
    </div>
</div>

<div id="block-filtering-modal" class="modal fade" tabindex="-1" aria-labelledby="block-filtering-modal-label" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title fw-bold" id="block-filtering-modal-label"><?= __('Node Filtering') ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <p><?= __('Node filtering') ?></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-success" onclick="saveFilteringForModule(this)"><?= __('Save') ?></button>
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Close') ?></button>
            </div>
        </div>
    </div>
</div>

<?= $this->element('/Workflows/infoModal') ?>

<?php
/*
 * jQuery, jQuery UI and Chosen are loaded here rather than in the layout: this
 * is the only Overmind page that needs them, and the rest of the theme stays
 * jQuery-free. Order matters — jQuery first, then its plugins, then the compat
 * bridge, then the editor itself.
 */
echo $this->element('genericElements/assetLoader', [
    'css' => ['chosen.min'],
    'js' => ['jquery', 'jquery-ui.min', 'chosen.jquery.min'],
]);
echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min', 'drawflow-default'],
    'js' => ['drawflow', 'doT', 'moment.min', 'viselect.cjs'],
]);
echo $this->element('genericElements/assetLoader', [
    'css' => ['workflows-editor', 'workflows-editor-bs5'],
    'js' => ['workflows-editor/workflows-editor-bs5-compat', 'workflows-editor/workflows-editor', 'taskScheduler'],
]);
echo $this->element('genericElements/assetLoader', [
    'js' => [
        'codemirror/codemirror',
        'codemirror/addons/closebrackets',
        'codemirror/addons/placeholder',
    ],
    'css' => [
        'codemirror',
    ]
]);
?>

<script>
    var $root_container = $('.root-container')
    var $side_panel = $('.root-container .side-panel')
    var $canvas = $('.root-container .canvas')
    var $loadingBackdrop = $('.root-container .canvas #loadingBackdrop')
    var $chosenBlocks = $('.root-container .side-panel .chosen-container.blocks')
    var $blockFilterGroup = $('.root-container .side-panel #block-filter-group')
    var $drawflow = $('#drawflow')
    var $blockModal = $('#block-modal')
    var $blockModalDeleteButton = $blockModal.find('#delete-selected-node')
    var $blockNotificationModal = $('#block-notifications-modal')
    var $blockFilteringModal = $('#block-filtering-modal')
    var $controlDuplicateButton = $('.control-buttons #control-duplicate')
    var $controlFrameNodeButton = $('.control-buttons #control-frame-node')
    var $controlDeleteButton = $('.control-buttons #control-delete')
    var $controlExportBlocksLi = $('.control-buttons #control-export-blocks')
    var $controlSaveBlocksLi = $('.control-buttons #control-save-blocks')
    var $controlEditBlocksLiContainer = $('.control-buttons #control-import-blocks-container')
    var $controlEditBlocksLis = $('.control-buttons .control-edit-bp-blocks')
    var $importWorkflowButton = $('#importWorkflow')
    var $exportWorkflowButton = $('#exportWorkflow')
    var $saveWorkflowButton = $('#saveWorkflow')
    var $toggleWorkflowButton = $('#workflow-debug-button')
    var $runWorkflowButton = $('#workflow-run-button')
    var $saveBlueprintButton = $('#saveBlueprint')
    var $lastModifiedField = $('#lastModifiedField')
    var $workflowSavedIconContainer = $('#workflow-saved-container')
    var $workflowSavedIconText = $('#workflow-saved-text')
    var $workflowSavedIconTextDetails = $('#workflow-saved-text-details')
    var $blockContainerLogic = $('#container-logic')
    var $blockContainerAction = $('#container-actions')
    var editor = false
    var selection = false
    /*
     * workflows-editor.js reads `saveFailedMessage` in its ajax error handlers
     * but nothing ever defines it — including the legacy view — so a failed
     * fetch/save threw a ReferenceError instead of reporting the real problem.
     * Declaring it here fixes that without touching the editor script.
     */
    var saveFailedMessage = '<?= __('Could not reach the workflow API. Reason') ?>'
    var all_modules = <?= json_encode($allModules) ?>;
    var all_modules_by_id = <?= json_encode(Hash::combine($allModules, '{n}.id', '{n}')) ?>;
    var all_triggers_by_id = <?= json_encode(Hash::combine($triggerModules, '{n}.id', '{n}')) ?>;
    var all_workflow_blueprints_by_id = <?= json_encode(Hash::combine($workflowBlueprints, '{n}.WorkflowBlueprint.id', '{n}')) ?>;
    var workflow = false
    var workflowTriggerId = false
    <?php if (!empty($selectedWorkflow)) : ?>
        workflow = <?= json_encode($selectedWorkflow) ?>;
        workflowTriggerId = '<?= h($workflowTriggerId) ?>';
    <?php endif; ?>

    $(document).ready(function() {
        initDrawflow()
        $('.sidebar-minimize-button').click(function() {
            $(this).closest('.sidebar').addClass('minimized')
        })
        $('.sidebar-maximize-button').click(function() {
            $(this).closest('.sidebar').removeClass('minimized')
        })
    })
</script>
