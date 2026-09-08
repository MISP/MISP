<?php
$jobs = $jobs ?? [];
$nb = count($jobs);
?>

<div class="card shadow-sm w-100 border-0">
    <div class="card-header bg-transparent">
        <h4 class="card-title mb-2 mt-2">
            <i class="fas fa-trash text-danger me-2"></i>
            <?= $nb === 1 ? __('Delete job entry') : __('Delete job entries') ?>
        </h4>
    </div>

    <div class="card-body">
        <p class="mb-2">
            <?= $nb === 1
                ? __('Are you sure you want to delete this job entry?')
                : __('Are you sure you want to delete these <strong>%s</strong> job entries?', $nb) ?>
        </p>
        <p class="text-muted small mb-3">
            <i class="fas fa-circle-info me-1"></i>
            <?= __('Job entries are log records only — deleting them has no impact on running jobs.') ?>
        </p>

        <?php if ($nb > 0): ?>
            <ul class="list-group mb-3">
                <?php foreach ($jobs as $j): ?>
                    <li class="list-group-item">
                        <div class="d-flex align-items-center gap-2">
                            <span class="badge text-bg-light border">#<?= h($j['Job']['id']) ?></span>
                            <?php if (!empty($j['Job']['worker'])): ?>
                                <span class="badge rounded-pill text-bg-secondary">
                                    <?= h($j['Job']['worker']) ?>
                                </span>
                            <?php endif; ?>
                            <span class="fw-semibold text-break">
                                <?= h($j['Job']['job_type'] ?? __('Unknown')) ?>
                            </span>
                        </div>
                        <?php if (!empty($j['Job']['message'])): ?>
                            <div class="text-body-secondary small text-break mt-1">
                                <?= h($j['Job']['message']) ?>
                            </div>
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <?php
            echo $this->Form->create('Job', [
                'id' => 'PromptForm',
                'url' => $baseurl . '/jobs/deleteSelection',
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
