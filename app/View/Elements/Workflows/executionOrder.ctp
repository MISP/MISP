<div>
    <?php if (!empty($trigger['Workflows']['blocking'])): ?>
        <ul class="unstyled">
            <li class="bold">
                <i class="bold fa-fw <?= $this->FontAwesome->getClass('hourglass-start') ?>" style="font-size: larger;" title="<?= __('Blocking execution path') ?>"></i>
                <?= __('Blocking') ?>
            </li>
            <?php foreach ($trigger['Workflows']['blocking'] as $i => $workflow) : ?>
                <li>
                    <i class="fa-fw fa-rotate-90 <?= $this->FontAwesome->getClass(empty($workflow['Workflow']['enabled']) ? 'arrow-right' : 'level-up-alt') ?>" style="margin-left: <?= $i+1 ?>em"></i>
                    <a
                        href="<?= $baseurl . '/workflows/view/' . h($workflow['Workflow']['id']) ?>"
                        title="<?= empty($workflow['Workflow']['enabled']) ? __('This workflow is disabled') : h($workflow['Workflow']['description']) ?>"
                        class="<?= empty($workflow['Workflow']['enabled']) ? 'muted' : '' ?>"
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
    <?php endif; ?>
    <?php if (!empty($trigger['Workflows']['non-blocking'])): ?>
        <ul class="unstyled">
            <li class="bold">
                <i class="fa-fw <?= $this->FontAwesome->getClass('random') ?>" title="<?= __('Parallel execution path') ?>"></i>
                <?= __('Parallel') ?>
            </li>
            <?php foreach ($trigger['Workflows']['non-blocking'] as $i => $workflow) : ?>
                <li>
                    <i class="fa-fw <?= $this->FontAwesome->getClass('arrow-right') ?>" title="<?= __('Parallel execution path') ?>" style="margin-left: <?= 1 ?>em"></i>
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
    <?php endif; ?>
</div>