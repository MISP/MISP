<?php
$usableModules = [
    'blocks_action' => $modules['blocks_action'],
    'blocks_logic' => $modules['blocks_logic'],
];
$allModules = array_merge($usableModules['blocks_action'], $usableModules['blocks_logic']);
$triggerModules = $modules['blocks_trigger'];
?>
<div class="root-container">
    <div class="main-container">
        <div class="side-panel">
            <a href="<?= $baseurl . '/workflows/triggers' ?>">
                <i class="fa-fw <?= $this->FontAwesome->getClass('caret-left') ?>"></i>
                <?= __('Trigger index') ?>
            </a>
            <h3>
                <span style="font-weight:normal;"><?= __('Workflows:') ?></span>
                <strong><?= h($selectedWorkflow['Workflow']['trigger_id']) ?></strong>
            </h3>
            <div class="" style="margin-top: 0.5em;">
                <div class="btn-group" style="margin-left: 3px;">
                    <a class="btn btn-primary dropdown-toggle" data-toggle="dropdown" href="#"><?= __('More Actions') ?> <span class="caret"></span></a>
                    <ul class="dropdown-menu">
                        <li><a id="importWorkflow" href="<?= $baseurl . '/workflows/import/' ?>"><i class="fa-fw <?= $this->FontAwesome->getClass('file-import') ?>"></i> <?= __('Import workflow') ?></a></li>
                        <li><a id="exportWorkflow" href="<?= $baseurl . '/workflows/export/' . h($selectedWorkflow['Workflow']['id']) ?>"><i class="fa-fw <?= $this->FontAwesome->getClass('file-export') ?>"></i> <?= __('Export workflow') ?></a></li>
                    </ul>
                </div>
                <button id="saveWorkflow" class="btn btn-primary" href="#">
                    <i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?>
                    <span class="fa fa-spin fa-spinner loading-span hidden"></span>
                </button>
            </div>
            <div class="" style="margin-top: 0.25em;">
                <span id="lastModifiedField" title="<?= __('Last updated') ?>" class="last-modified label">2 days ago</span>
            </div>

            <h3>Blocks</h3>
            <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off">
                <?php foreach ($allModules as $block) : ?>
                    <option value="<?= h($block['id']) ?>"><?= h($block['name']) ?></option>
                <?php endforeach; ?>
            </select>

            <ul class="nav nav-tabs" id="block-tabs">
                <li class="active"><a href="#container-actions">
                        <i class="<?= $this->FontAwesome->getClass('play') ?>"></i>
                        Actions
                    </a></li>
                <li><a href="#container-logic">
                        <i class="<?= $this->FontAwesome->getClass('code-branch') ?>"></i>
                        Logic
                    </a></li>
            </ul>

            <div class="tab-content">
                <div class="tab-pane active" id="container-actions">
                    <?php foreach ($modules['blocks_action'] as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
                <div class="tab-pane" id="container-logic">
                    <?php foreach ($modules['blocks_logic'] as $block) : ?>
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
    var $blockNotificationModal = $('#block-notifications-modal')
    var $importWorkflowButton = $('#importWorkflow')
    var $exportWorkflowButton = $('#exportWorkflow')
    var $saveWorkflowButton = $('#saveWorkflow')
    var $lastModifiedField = $('#lastModifiedField')
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