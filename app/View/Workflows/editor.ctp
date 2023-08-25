<?php
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
?>
<div class="root-container">
    <div class="topbar">
        <a href="<?= $baseurl . '/workflows/triggers' ?>">
            <i class="fa-fw <?= $this->FontAwesome->getClass('caret-left') ?>"></i><?= __('Trigger index') ?>
        </a>
        <span style="display: flex; align-items: center; min-width: 220px; gap: 5px;">
            <h3 style="display: inline-block;">
                <span style="font-weight:normal;"><?= __('Workflow:') ?></span>
                <strong><?= h($selectedWorkflow['Workflow']['trigger_id']) ?></strong>
            </h3>
            <?php if (!empty($isBlockingTrigger)) : ?>
                <span class="label label-important" style="line-height: 20px;" title="<?= __('This workflow is a blocking worklow and can prevent the default MISP behavior to execute') ?>">
                    <i class="fa-lg fa-fw <?= $this->FontAwesome->getClass('stop-circle') ?>"></i>
                    <?= __('Blocking') ?>
                </span>
            <?php else : ?>
                <span class="label label-success" style="line-height: 20px;" title="<?= __('This workflow is a not blocking worklow. The default MISP behavior will or has already happened') ?>">
                    <i class="fa-lg fa-fw <?= $this->FontAwesome->getClass('check-circle') ?>"></i>
                    <?= __('Non blocking') ?>
                </span>
            <?php endif; ?>
            <?php if (!empty($isMISPFormat)) : ?>
                <span class="label label-important" style="line-height: 20px; background-color: #009fdc;" title="<?= __('The data passed by this trigger is compliant with the MISP core format') ?>">
                    <img src="/img/misp-logo-no-text.png" alt="MISP Core format" width="18" height="18" style="filter: brightness(0) invert(1);">
                </span>
            <?php endif; ?>
        </span>
        <span style="display: flex; align-items: center;">
            <button id="saveWorkflow" class="btn btn-primary" href="#">
                <i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?>
                <span class="fa fa-spin fa-spinner loading-span hidden"></span>
            </button>
            <span id="workflow-saved-container" class="fa-stack" style="margin-left: 0.75em;">
                <i class="<?= $this->FontAwesome->getClass('cloud') ?> fa-stack-2x"></i>
                <i class="<?= $this->FontAwesome->getClass('save') ?> fa-stack-1x fa-inverse" style="top: 0.15em;"></i>
            </span>
            <span id="workflow-saved-text" style="margin-left: 5px;"></span>
            <span id="workflow-saved-text-details" style="margin-left: 5px; font-size: 0.75em"></span>
        </span>
        <span style="display: flex; align-items: center; margin-left: auto; margin-right: 1em; gap: 1em;">
            <button id="workflow-debug-button" class="btn btn-<?= $debugEnabled ? 'success' : 'primary' ?>" data-enabled="<?= $debugEnabled ? '1' : '0' ?>">
                <i class="<?= $this->FontAwesome->getClass('bug') ?> fa-fw"></i>
                <?= __('Debug Mode: ') ?>
                <b class="state-text" data-on="<?= __('On') ?>" data-off="<?= __('Off') ?>"><?= $debugEnabled ? __('On') : __('Off') ?></b>
            </button>
            <button id="workflow-run-button" class="btn btn-primary" <?= $debugEnabled ? '' : 'disabled' ?>>
                <i class="<?= $this->FontAwesome->getClass('play') ?> fa-fw"></i>
                <?= __('Run Workflow') ?>
            </button>
            <a href="<?= $baseurl . '/admin/logs/index/model:Workflow/action:execute_workflow/model_id:' . h($selectedWorkflow['Workflow']['id']) ?>" title="<?= __('View execution logs') ?>" aria-label="<?= __('View execution logs') ?>">
                <i class="<?= $this->FontAwesome->getClass('list-alt') ?>"></i> <?= __('Execution logs') ?>
            </a>
            <button class="btn btn-info btn-mini" href="#workflow-info-modal" data-toggle="modal" title="<?= __('View help') ?>">
                <i class="<?= $this->FontAwesome->getClass('info-circle') ?>"></i>
            </button>
        </span>
    </div>

    <div class="main-container">
        <div class="sidebar">
            <div class="side-panel">
                <span class="sidebar-minimize-button">
                    <i class="<?= $this->FontAwesome->getClass('angle-double-left') ?>"></i>
                </span>
                <span class="sidebar-maximize-button">
                    <i class="<?= $this->FontAwesome->getClass('angle-double-right') ?>"></i>
                </span>
                <ul class="nav nav-tabs" id="block-tabs">
                    <li class="active">
                        <a href="#container-actions">
                            <i class="<?= $this->FontAwesome->getClass('play') ?>"></i>
                            <?= __('Actions') ?>
                        </a>
                    </li>
                    <li>
                        <a href="#container-logic">
                            <i class="<?= $this->FontAwesome->getClass('code-branch') ?>"></i>
                            <?= __('Logic') ?>
                        </a>
                    </li>
                    <li>
                        <a href="#container-blueprints">
                            <i class="<?= $this->FontAwesome->getClass('shapes') ?>"></i>
                            <?= __('Blueprints') ?>
                        </a>
                    </li>
                </ul>

                <div class="tab-content">
                    <div class="tab-pane active" id="container-actions">
                        <div id="block-filter-group" class="btn-group" data-toggle="buttons-radio">
                            <button type="button" class="btn btn-primary active" data-type="enabled" onclick="filterModules(this)"><?= __('Enabled') ?></button>
                            <button type="button" class="btn btn-primary" data-type="misp-module" onclick="filterModules(this)">
                                misp-module<span class="is-misp-module"></span>
                            </button>
                            <button type="button" class="btn btn-primary" data-type="is-blocking" onclick="filterModules(this)">
                                <?= __('Blocking') ?>
                            </button>
                            <button type="button" class="btn btn-primary" data-type="all" onclick="filterModules(this)"><?= __('All') ?></button>
                        </div>
                        <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off">
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
                                <div class="alert alert-danger" style="margin: 10px 5px;">
                                    <?= __('There are no modules available. They can be enabled %s.', sprintf('<a href="%s">%s</a>', $baseurl . '/workflows/moduleIndex', __('here'))) ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="tab-pane" id="container-logic">
                        <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off" style="width: 305px; margin: 0 0.5em;">
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
                            <div class="alert alert-danger" style="margin-top: 10px;">
                                <?= __('There are no modules available. They can be enabled %s.', sprintf('<a href="%s">%s</a>', $baseurl . '/workflows/moduleIndex/type:logic', __('here'))) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                    <div class="tab-pane" id="container-blueprints">
                        <div style="margin-left: 0.75em; margin-bottom: 0.5em;">
                            <a id="saveBlueprint" class="btn btn-primary" href="<?= $baseurl . '/workflowBlueprints/add/1' ?>">
                                <i class="<?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save blueprint') ?>
                            </a>
                        </div>
                        <select type="text" placeholder="Search for a block" class="chosen-container blocks blueprint-select" autocomplete="off" style="width: 305px; margin: 0 0.5em;">
                            <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                <option value="<?= h($workflowBlueprint['WorkflowBlueprint']['id']) ?>"><?= h($workflowBlueprint['WorkflowBlueprint']['name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="block-container">
                            <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                <?= $this->element('Workflows/sidebar-block-workflow-blueprint', ['workflowBlueprint' => $workflowBlueprint['WorkflowBlueprint']]) ?>
                            <?php endforeach; ?>
                            <?php if (empty($workflowBlueprints)) : ?>
                                <div class="alert alert-info" style="margin-top: 10px;">
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
                <div class="btn-group control-buttons">
                    <button id="control-duplicate" class="btn btn-small btn-primary disabled" type="button" title="<?= __('Duplicate') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('clone') ?>"></i> <?= __('Duplicate') ?>
                    </button>
                    <button id="control-frame-node" class="btn btn-small btn-primary disabled" type="button" title="<?= __('Create frame node') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('object-group') ?>"></i> <?= __('Frame') ?>
                    </button>
                    <button id="control-delete" class="btn btn-small btn-danger disabled" type="button" title="<?= __('Delete') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('trash') ?>"></i> <?= __('Delete') ?>
                    </button>
                    <a class="btn btn-primary btn-small dropdown-toggle" data-toggle="dropdown" href="#">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('shapes') ?>"></i> <?= __('Blueprints') ?> <span class="caret"></span>
                    </a>
                    <ul class="dropdown-menu pull-right">
                        <li id="control-import-blocks" class="dropdown-submenu submenu-right">
                            <a href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-import') ?>"></i> <?= __('Import blueprint') ?></a>
                            <ul class="dropdown-menu pull-right">
                                <?php if (empty($workflowBlueprints)) : ?>
                                    <li><a href="#"><?= __('No workflow blueprints saved') ?></a></li>
                                <?php endif; ?>
                                <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                    <li>
                                        <a href="#" title="<?= h($workflowBlueprint['WorkflowBlueprint']['description']) ?>" onclick="addWorkflowBlueprint(<?= h($workflowBlueprint['WorkflowBlueprint']['id']) ?>)">
                                            <?= h($workflowBlueprint['WorkflowBlueprint']['name']) ?>
                                            <small class="text-muted">[<?= h(substr($workflowBlueprint['WorkflowBlueprint']['uuid'], 0, 4)) ?>...]</small>
                                        </a>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <li id="control-save-blocks" class="disabled">
                            <a href="<?= $baseurl . '/workflowBlueprints/add/1' ?>"><i class=" fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save blueprint') ?></a>
                        </li>
                        <li id="control-import-blocks-container" class="dropdown-submenu submenu-right disabled">
                            <a href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('edit') ?>"></i> <?= __('Edit existing blueprint') ?></a>
                            <ul class="dropdown-menu pull-right disabled">
                                <?php if (empty($workflowBlueprints)) : ?>
                                    <li><a href="#"><?= __('No workflow blueprints saved') ?></a></li>
                                <?php endif; ?>
                                <?php foreach ($workflowBlueprints as $workflowBlueprint) : ?>
                                    <li class="control-edit-bp-blocks">
                                        <a href="<?= $baseurl . '/workflowBlueprints/edit/' . h($workflowBlueprint['WorkflowBlueprint']['id']) ?>" title="<?= h($workflowBlueprint['WorkflowBlueprint']['description']) ?>" data-bp-id="<?= h($workflowBlueprint['WorkflowBlueprint']['id']) ?>">
                                            <?= h($workflowBlueprint['WorkflowBlueprint']['name']) ?>
                                            <small class="text-muted">[<?= h(substr($workflowBlueprint['WorkflowBlueprint']['uuid'], 0, 4)) ?>...]</small>
                                        </a>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </li>
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

<div id="block-modal" class="modal hide fade modal-lg" tabindex="-1" role="dialog" aria-labelledby="Module block modal" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?= __('Node settings') ?></h3>
    </div>
    <div class="modal-body modal-body-xl">
        <p><?= __('Node settings') ?></p>
    </div>
    <div class="modal-footer">
        <button id="delete-selected-node" class="btn btn-danger" style="float: left;"><?= __('Delete node') ?></button>
        <button class="btn" data-dismiss="modal" aria-hidden="true"><?= __('Close') ?></button>
    </div>
</div>

<div id="block-notifications-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="Module notification modal" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?= __('Node Notifications') ?></h3>
    </div>
    <div class="modal-body">
        <p><?= __('Node notifications') ?></p>
    </div>
    <div class="modal-footer">
        <button class="btn" data-dismiss="modal" aria-hidden="true"><?= __('Close') ?></button>
    </div>
</div>

<div id="block-filtering-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="Module filtering modal" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?= __('Node Filtering') ?></h3>
    </div>
    <div class="modal-body">
        <p><?= __('Node filtering') ?></p>
    </div>
    <div class="modal-footer">
        <button class="btn btn-success" onclick="saveFilteringForModule(this)" aria-hidden="true"><?= __('Save') ?></button>
        <button class="btn" data-dismiss="modal" aria-hidden="true"><?= __('Close') ?></button>
    </div>
</div>

<?= $this->element('/Workflows/infoModal') ?>

<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min', 'drawflow-default'],
    'js' => ['jquery-ui.min', 'drawflow', 'doT', 'moment.min', 'viselect.cjs'],
    // 'js' => ['jquery-ui.min', 'drawflow.min', 'doT', 'moment.min', 'viselect.cjs'],
]);
echo $this->element('genericElements/assetLoader', [
    'css' => ['workflows-editor'],
    'js' => ['workflows-editor/workflows-editor', 'taskScheduler'],
]);
echo $this->element('genericElements/assetLoader', [
    'js' => array(
        'codemirror/codemirror',
        'codemirror/addons/closebrackets',
    ),
    'css' => array(
        'codemirror',
    )
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