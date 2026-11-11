<?php
$tasks = $tasks ?? [];
$nb = count($tasks);
?>

<div class="card shadow-sm w-100 border-0">
    <div class="card-header bg-transparent">
        <h4 class="card-title mb-2 mt-2">
            <i class="fas fa-trash text-danger me-2"></i>
            <?= $nb === 1 ? __('Delete scheduled task') : __('Delete scheduled tasks') ?>
        </h4>
    </div>

    <div class="card-body">
        <p class="mb-3">
            <?= $nb === 1
                ? __('Are you sure you want to delete this scheduled task?')
                : __('Are you sure you want to delete these <strong>%s</strong> scheduled tasks?', $nb) ?>
        </p>

        <?php if ($nb > 0): ?>
            <ul class="list-group mb-3">
                <?php foreach ($tasks as $t): ?>
                    <li class="list-group-item">
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <div class="bg-light rounded px-2 py-1">#<?= h($t['Task']['id']) ?></div>
                            <?= $this->element('genericElementsBS5/Badges/type', [
                                'type' => $t['Task']['type'],
                            ]) ?>
                        </div>
                        <?= $this->element('genericElementsBS5/IndexTable/Fields/task_action', [
                            'row' => $t,
                            'field' => ['data_path' => 'Task.action'],
                        ]) ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <?php
            echo $this->Form->create('Task', [
                'id' => 'PromptForm',
                'url' => $baseurl . '/tasks/deleteSelection',
                'class' => 'm-0'
            ]);
            echo $this->Form->hidden('id');
        ?>

        <div class="d-flex justify-content-between align-items-center">
            <button type="submit" class="btn btn-danger">
                <?= __('Yes'); ?>
            </button>
            <button
                type="button"
                class="btn btn-outline-secondary"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                <?= __('No'); ?>
            </button>
        </div>

        <?= $this->Form->end(); ?>
    </div>
</div>
