<?php
$trigger['execution_order'] = [
    ['name' => 'test1', 'id' => 1, 'enabled' => true, 'description' => 'test', 'Organisation' => ['id'=>1, 'name'=>'ORGNAME']],
    ['name' => 'test2', 'id' => 1, 'enabled' => false, 'description' => 'test', 'Organisation' => ['id'=>1, 'name'=>'ORGNAME']],
    ['name' => 'test3', 'id' => 1, 'enabled' => true, 'description' => 'test', 'Organisation' => ['id'=>1, 'name'=>'ORGNAME']]
];
?>
<div>
    <ul class="unstyled">
        <?php foreach ($trigger['execution_order'] as $i => $workflow) : ?>
            <li>
                <?php if ($i == 0) : ?>
                    <i class="fa-fw <?= $this->FontAwesome->getClass('hourglass-start') ?>" style="font-size: larger;" title="<?= __('Blocking execution path') ?>"></i>
                <?php else : ?>
                    <i class="fa-fw fa-rotate-90 <?= $this->FontAwesome->getClass(empty($workflow['enabled']) ? 'arrow-right' : 'level-up-alt') ?>" style="margin-left: <?= $i ?>em"></i>
                <?php endif; ?>
                <a
                    href="<?= $baseurl . '/workflows/view/' . h($workflow['id']) ?>"
                    title="<?= empty($workflow['enabled']) ? __('This workflow is disabled') : h($workflow['description']) ?>"
                    class="bold <?= empty($workflow['enabled']) ? 'muted' : '' ?>"
                    style="<?= empty($workflow['enabled']) ? 'text-decoration: line-through;' : '' ?>"
                >
                    <?= h($workflow['name']) ?>
                </a>
                <span style="font-size: smaller;">
                    :: <?= $this->element('genericElements/SingleViews/Fields/orgField', ['data' => $workflow, 'field' => ['path' => '']]) ?>
                </span>
            </li>
        <?php endforeach; ?>
    </ul>
    <ul class="unstyled">
        <?php foreach ($trigger['execution_order'] as $i => $workflow) : ?>
            <li>
                <i class="fa-fw <?= $this->FontAwesome->getClass('arrow-right') ?>" title="<?= __('Parallel execution path') ?>"></i>
                <a
                    href="<?= $baseurl . '/workflows/view/' . h($workflow['id']) ?>"
                    title="<?= empty($workflow['enabled']) ? __('This workflow is disabled') : h($workflow['description']) ?>"
                    class="<?= empty($workflow['enabled']) ? 'muted' : '' ?>"
                    style="<?= empty($workflow['enabled']) ? 'text-decoration: line-through;' : '' ?>"
                >
                    <?= h($workflow['name']) ?>
                </a>
            </li>
        <?php endforeach; ?>
    </ul>
</div>