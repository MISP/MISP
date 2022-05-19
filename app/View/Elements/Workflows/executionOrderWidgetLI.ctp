<li data-workflowid="<?= h($workflow['Workflow']['id']) ?>">
    <i class="<?= $this->FontAwesome->getClass('arrows-alt-v') ?>"></i>
    <div>
        <div style="display: flex;">
            <strong
                title="<?= empty($workflow['Workflow']['enabled']) ? __('This workflow is disabled') : h($workflow['Workflow']['description']) ?>"
                class="<?= empty($workflow['Workflow']['enabled']) ? 'muted' : '' ?>"
                style="font-size: larger; <?= empty($workflow['Workflow']['enabled']) ? 'text-decoration: line-through;' : '' ?>"
            >
                <?= h($workflow['Workflow']['name']) ?>
            </strong>
            <span style="font-size: smaller; margin-left: auto;">
                <?= $this->element('genericElements/SingleViews/Fields/orgField', ['data' => $workflow, 'field' => ['path' => 'Organisation']]) ?>
            </span>
        </div>
        <div class="muted ellipsis-overflow">
            <?= h($workflow['Workflow']['description']) ?>
        </div>
    </div>
</li>