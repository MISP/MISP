<div>
    <?php if (empty($trigger['GroupedWorkflows']['blocking']) && empty($trigger['GroupedWorkflows']['non-blocking'])): ?>
        <?= __('No workflows listen to this trigger') ?>
    <?php endif; ?>
    <?php if (!empty($trigger['GroupedWorkflows']['blocking'])): ?>
        <ul class="unstyled">
            <li class="bold">
                <i class="bold fa-fw <?= $this->FontAwesome->getClass('hourglass-start') ?>" style="font-size: larger;" title="<?= __('Blocking execution path') ?>"></i>
                <?= __('Blocking') ?>
            </li>
            <?php foreach ($trigger['GroupedWorkflows']['blocking'] as $i => $workflow) : ?>
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
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
    <?php if (!empty($trigger['GroupedWorkflows']['non-blocking'])): ?>
        <ul class="unstyled">
            <li class="bold">
                <i class="fa-fw <?= $this->FontAwesome->getClass('random') ?>" title="<?= __('Concurrent execution path') ?>"></i>
                <?= __('Concurrent') ?>
            </li>
            <?php foreach ($trigger['GroupedWorkflows']['non-blocking'] as $i => $workflow) : ?>
                <li>
                    <i class="fa-fw <?= $this->FontAwesome->getClass('arrow-right') ?>" title="<?= __('Concurrent execution path') ?>" style="margin-left: <?= 1 ?>em"></i>
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