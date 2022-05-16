<div>
    <ul class="unstyled">
        <?php foreach ($trigger['Workflows']['blocking'] as $i => $workflow) : ?>
            <li>
                <?php if ($i == 0) : ?>
                    <i class="fa-fw <?= $this->FontAwesome->getClass('hourglass-start') ?>" style="font-size: larger;" title="<?= __('Blocking execution path') ?>"></i>
                <?php else: ?>
                    <i class="fa-fw fa-rotate-90 <?= $this->FontAwesome->getClass(empty($workflow['Workflow']['enabled']) ? 'arrow-right' : 'level-up-alt') ?>" style="margin-left: <?= $i ?>em"></i>
                <?php endif; ?>
                <a
                    href="<?= $baseurl . '/workflows/view/' . h($workflow['Workflow']['id']) ?>"
                    title="<?= empty($workflow['Workflow']['enabled']) ? __('This workflow is disabled') : h($workflow['Workflow']['description']) ?>"
                    class="bold <?= empty($workflow['Workflow']['enabled']) ? 'muted' : '' ?>"
                    style="<?= empty($workflow['Workflow']['enabled']) ? 'text-decoration: line-through;' : '' ?>"
                >
                    <?= h($workflow['Workflow']['name']) ?>
                </a>
                <span style="font-size: smaller;">
                    :: <?= $this->element('genericElements/SingleViews/Fields/orgField', ['data' => $workflow, 'field' => ['path' => 'Organisation']]) ?>
                </span>
            </li>
        <?php endforeach; ?>
    </ul>
    <ul class="unstyled">
        <?php foreach ($trigger['Workflows']['non-blocking'] as $i => $workflow) : ?>
            <li>
                <i class="fa-fw <?= $this->FontAwesome->getClass('arrow-right') ?>" title="<?= __('Parallel execution path') ?>"></i>
                <a
                    href="<?= $baseurl . '/workflows/view/' . h($workflow['Workflow']['id']) ?>"
                    title="<?= empty($workflow['Workflow']['enabled']) ? __('This workflow is disabled') : h($workflow['Workflow']['description']) ?>"
                    class="<?= empty($workflow['Workflow']['enabled']) ? 'muted' : '' ?>"
                    style="<?= empty($workflow['Workflow']['enabled']) ? 'text-decoration: line-through;' : '' ?>"
                >
                    <?= h($workflow['Workflow']['name']) ?>
                </a>
            </li>
        <?php endforeach; ?>
    </ul>
</div>