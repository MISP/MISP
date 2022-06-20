<?php
$usableModules = [
    'blocks_action' => $modules['blocks_action'],
    'blocks_logic' => $modules['blocks_logic'],
];
$allModules = array_merge($usableModules['blocks_action'], $usableModules['blocks_logic']);
$triggerModules = $modules['blocks_trigger'];
?>
<div class="root-container">
    <div class="topbar">
        <a href="<?= $baseurl . '/workflows/triggers' ?>">
            <i class="fa-fw <?= $this->FontAwesome->getClass('caret-left') ?>"></i><?= __('Trigger index') ?>
        </a>
        <span style="display: flex; align-items: center; min-width: 220px;">
            <h3 style="display: inline-block;">
                <span style="font-weight:normal;"><?= __('Workflow:') ?></span>
                <strong><?= h($selectedWorkflow['Workflow']['trigger_id']) ?></strong>
            </h3>
        </span>
        <span style="display: flex; align-items: center;">
            <button id="saveWorkflow" class="btn btn-primary" href="#">
                <i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?>
                <span class="fa fa-spin fa-spinner loading-span hidden"></span>
            </button>
            <span id="workflow-saved-container" class="fa-stack small" style="margin-left: 0.75em;">
                <i class=" fas fa-cloud fa-stack-2x"></i>
                <i class="fas fa-save fa-stack-1x fa-inverse" style="top: 0.15em;"></i>
            </span>
            <span id="workflow-saved-text" style="margin-left: 5px;"></span>
            <span id="workflow-saved-text-details" style="margin-left: 5px; font-size: 0.75em"></span>
        </span>
    </div>

    <div class="main-container">
        <div class="sidebar">
            <div class="side-panel">
                <ul class="nav nav-tabs" id="block-tabs">
                    <li class="active">
                        <a href="#container-actions">
                            <i class="<?= $this->FontAwesome->getClass('play') ?>"></i>
                            Actions
                        </a>
                    </li>
                    <li>
                        <a href="#container-logic">
                            <i class="<?= $this->FontAwesome->getClass('code-branch') ?>"></i>
                            Logic
                        </a>
                    </li>
                </ul>

                <div class="tab-content">
                    <div class="tab-pane active" id="container-actions">
                        <div id="block-filter-group" class="btn-group" data-toggle="buttons-radio">
                            <button type="button" class="btn btn-primary active" data-type="enabled" onclick="filterBlocks(this)">Enabled</button>
                            <button type="button" class="btn btn-primary" data-type="misp-module" onclick="filterBlocks(this)">
                                misp-module
                                <sup class="fab fa-python"></sup>
                            </button>
                            <button type="button" class="btn btn-primary" data-type="is-blocking" onclick="filterBlocks(this)">blocking</button>
                            <button type="button" class="btn btn-primary" data-type="all" onclick="filterBlocks(this)">All</button>
                        </div>
                        <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off">
                            <?php foreach ($modules['blocks_action'] as $block) : ?>
                                <option value="<?= h($block['id']) ?>"><?= h($block['name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="block-container">
                            <?php foreach ($modules['blocks_action'] as $block) : ?>
                                <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="tab-pane" id="container-logic">
                        <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off" style="width: 305px; margin: 0 0.5em;">
                            <?php foreach ($modules['blocks_logic'] as $block) : ?>
                                <option value="<?= h($block['id']) ?>"><?= h($block['name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <div class="block-container">
                            <?php foreach ($modules['blocks_logic'] as $block) : ?>
                                <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                            <?php endforeach; ?>
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
                    <button id="control-delete" class="btn btn-small btn-danger disabled" type="button" title="<?= __('Delete') ?>">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('trash') ?>"></i> <?= __('Delete') ?>
                    </button>
                    <a class="btn btn-primary btn-small dropdown-toggle" data-toggle="dropdown" href="#">
                        <i class="fa-fw <?= $this->FontAwesome->getClass('shapes') ?>"></i> <?= __('Workflow parts') ?> <span class="caret"></span>
                    </a>
                    <ul class="dropdown-menu pull-right">
                        <li id="control-import-blocks" class=""><a href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-import') ?>"></i> <?= __('Import workflow parts') ?></a></li>
                        <li id="control-export-blocks" class="disabled"><a href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-export') ?>"></i> <?= __('Export workflow parts') ?></a></li>
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

<div id="block-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="Module block modal" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3>Block options</h3>
    </div>
    <div class="modal-body">
        <p>Block options</p>
    </div>
    <div class="modal-footer">
        <button id="delete-selected-node" class="btn btn-danger">Delete</button>
        <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
    </div>
</div>

<div id="block-notifications-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="Module notification modal" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?= __('Module Notifications') ?></h3>
    </div>
    <div class="modal-body">
        <p>Block notifications</p>
    </div>
    <div class="modal-footer">
        <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
    </div>
</div>

<div id="block-filtering-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="Module filtering modal" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?= __('Module Filtering') ?></h3>
    </div>
    <div class="modal-body">
        <p>Block filtering</p>
    </div>
    <div class="modal-footer">
        <button class="btn btn-success" onclick="saveFilteringForModule(this)" aria-hidden="true">Save</button>
        <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
    </div>
</div>

<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min', 'drawflow-default'],
    'js' => ['jquery-ui', 'drawflow.min', 'doT', 'moment.min', 'viselect.cjs'],
]);
echo $this->element('genericElements/assetLoader', [
    'css' => ['workflows-editor'],
    'js' => ['workflows-editor/workflows-editor', 'taskScheduler'],
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
    var $controlDeleteButton = $('.control-buttons #control-delete')
    var $controlExportBlocksLi = $('.control-buttons #control-export-blocks')
    var $importWorkflowButton = $('#importWorkflow')
    var $exportWorkflowButton = $('#exportWorkflow')
    var $saveWorkflowButton = $('#saveWorkflow')
    var $lastModifiedField = $('#lastModifiedField')
    var $workflowSavedIconContainer = $('#workflow-saved-container')
    var $workflowSavedIconText = $('#workflow-saved-text')
    var $workflowSavedIconTextDetails = $('#workflow-saved-text-details')
    var $blockContainerLogic = $('#container-logic')
    var $blockContainerAction = $('#container-actions')
    var editor = false
    var all_blocks = <?= json_encode($allModules) ?>;
    var all_blocks_by_id = <?= json_encode(Hash::combine($allModules, '{n}.id', '{n}')) ?>;
    var all_triggers_by_id = <?= json_encode(Hash::combine($triggerModules, '{n}.id', '{n}')) ?>;
    var workflow = false
    <?php if (!empty($selectedWorkflow)) : ?>
        var workflow = <?= json_encode($selectedWorkflow) ?>;
    <?php endif; ?>

    $(document).ready(function() {
        initDrawflow()
    })
</script>