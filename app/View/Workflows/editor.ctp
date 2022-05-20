<div class="root-container">
    <div class="main-container">
        <div class="side-panel">
            <a href="<?= $baseurl . '/workflows/index' ?>">
                <i class="fa-fw <?= $this->FontAwesome->getClass('caret-left') ?>"></i>
                <?= __('Workflow index') ?>
            </a>
            <h3>Workflows</h3>
            <div class="workflow-selector-container">
                <select type="text" placeholder="Load a workflow" class="chosen-container workflows" autocomplete="off">
                    <?php foreach ($workflows as $workflow) : ?>
                        <option value="<?= h($workflow['Workflow']['id']) ?>" <?= $selectedWorkflow['Workflow']['id'] == $workflow['Workflow']['id'] ? 'selected' : '' ?>><?= h($workflow['Workflow']['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="" style="margin-top: 0.5em;">
                <div class="btn-group" style="margin-left: 3px;">
                    <a class="btn btn-primary" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('plus') ?>"></i> <?= __('New') ?></a>
                    <a class="btn btn-primary dropdown-toggle" data-toggle="dropdown" href="#"><span class="caret"></span></a>
                    <ul class="dropdown-menu">
                        <li><a id="exportWorkflow" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-export') ?>"></i> <?= __('Export workflow') ?></a></li>
                        <li><a id="importWorkflow" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-import') ?>"></i> <?= __('Import workflow') ?></a></li>
                    </ul>
                </div>
                <button id="saveWorkflow" class="btn btn-primary" href="#">
                    <i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?>
                    <span class="fa fa-spin fa-spinner loading-span hidden"></span>
                </button>
                <button id="deleteWorkflow" class="btn btn-danger" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('trash') ?>"></i> <?= __('Delete') ?></button>
            </div>
            <div class="" style="margin-top: 0.25em;">
                <span id="lastModifiedField" title="<?= __('Last updated') ?>" class="last-modified label">2 days ago</span>
            </div>

            <h3>Blocks</h3>
            <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off">
                <?php foreach ($modules['blocks_all'] as $block) : ?>
                    <option value="<?= h($block['id']) ?>"><?= h($block['name']) ?></option>
                <?php endforeach; ?>
            </select>

            <ul class="nav nav-tabs" id="block-tabs">
                <li class="active"><a href="#container-triggers">
                        <i class="<?= $this->FontAwesome->getClass('flag') ?>"></i>
                        Triggers
                    </a></li>
                <li><a href="#container-logic">
                        <i class="<?= $this->FontAwesome->getClass('code-branch') ?>"></i>
                        Logic
                    </a></li>
                <li><a href="#container-actions">
                        <i class="<?= $this->FontAwesome->getClass('play') ?>"></i>
                        Actions
                    </a></li>
            </ul>

            <div class="tab-content">
                <div class="tab-pane active" id="container-triggers">
                    <?php foreach ($modules['blocks_trigger'] as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
                <div class="tab-pane" id="container-logic">
                    <?php foreach ($modules['blocks_logic'] as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
                <div class="tab-pane" id="container-actions">
                    <?php foreach ($modules['blocks_action'] as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
            </div>

        </div>
        <div class="canvas">
            <div id="drawflow" data-workflowid="<?= h($selectedWorkflow['Workflow']['id']) ?>"></div>
            <div id="loadingBackdrop" class="modal-backdrop" style="display: none;"></div>
        </div>
    </div>
</div>

<div id="block-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
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

<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min', 'drawflow-default'],
    'js' => ['jquery-ui', 'drawflow.min', 'doT', 'moment.min'],
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
    var $chosenWorkflows = $('.root-container .side-panel .chosen-container.workflows')
    var $chosenBlocks = $('.root-container .side-panel .chosen-container.blocks')
    var $drawflow = $('#drawflow')
    var $blockModal = $('#block-modal')
    var $blockModalDeleteButton = $blockModal.find('#delete-selected-node')
    var $importWorkflowButton = $('#importWorkflow')
    var $exportWorkflowButton = $('#exportWorkflow')
    var $saveWorkflowButton = $('#saveWorkflow')
    var $deleteWorkflowButton = $('#deleteWorkflow')
    var $lastModifiedField = $('#lastModifiedField')
    var $blockContainerTriggers = $('#container-triggers')
    var $blockContainerLogic = $('#container-logic')
    var $blockContainerAction = $('#container-actions')
    var editor = false
    var all_blocks = <?= json_encode($modules['blocks_all']) ?>;
    var workflow = false
    <?php if (!empty($workflow)) : ?>
        var workflow = <?= json_encode($selectedWorkflow) ?>;
    <?php endif; ?>

    $(document).ready(function() {
        initDrawflow()
    })
</script>