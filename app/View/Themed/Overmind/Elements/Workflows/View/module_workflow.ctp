<?php
/*
 * The workflow a trigger starts, and every workflow listening to it.
 */
$workflow = $data['Workflow'] ?? [];
$hasWorkflow = !empty($workflow['id']);
$listening = $data['listening_workflows'] ?? [];
$timestamp = (int)($workflow['timestamp'] ?? 0);
?>

<div class="card shadow-sm mb-3">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary-emphasis"
                 style="width:36px;height:36px;">
                <i class="fas fa-diagram-project"></i>
            </div>
            <div class="fw-bold lh-1"><?= __('Workflow') ?></div>
        </div>
    </div>

    <div class="p-3">
        <?php if (!$hasWorkflow): ?>
            <p class="text-muted small mb-0">
                <?= __('No workflow listens to this trigger yet. Open the editor to create one.') ?>
            </p>
        <?php else: ?>
            <dl class="row small mb-0 gy-2">
                <dt class="col-5 text-muted fw-semibold"><?= __('Name') ?></dt>
                <dd class="col-7 mb-0 text-break">
                    <a class="fw-semibold" href="<?= h($baseurl . '/workflows/editor/' . (int)$workflow['id']) ?>">
                        <?= h($workflow['name']) ?>
                    </a>
                    <span class="text-muted">#<?= (int)$workflow['id'] ?></span>
                </dd>

                <dt class="col-5 text-muted fw-semibold"><?= __('Runs') ?></dt>
                <dd class="col-7 mb-0"><?= h(number_format((int)$workflow['counter'])) ?></dd>

                <dt class="col-5 text-muted fw-semibold"><?= __('Debug mode') ?></dt>
                <dd class="col-7 mb-0">
                    <?php if (!empty($workflow['debug_enabled'])): ?>
                        <span class="badge rounded-pill text-bg-warning"><i class="fas fa-bug me-1"></i><?= __('On') ?></span>
                    <?php else: ?>
                        <span class="badge rounded-pill text-bg-secondary"><i class="fas fa-bug-slash me-1"></i><?= __('Off') ?></span>
                    <?php endif; ?>
                </dd>

                <?php if ($timestamp): ?>
                    <dt class="col-5 text-muted fw-semibold"><?= __('Last update') ?></dt>
                    <dd class="col-7 mb-0"><?= h(date('Y-m-d H:i', $timestamp)) ?></dd>
                <?php endif; ?>

                <dt class="col-5 text-muted fw-semibold"><?= __('UUID') ?></dt>
                <dd class="col-7 mb-0 font-monospace text-truncate" title="<?= h($workflow['uuid'] ?? '') ?>">
                    <?= h($workflow['uuid'] ?? '') ?>
                </dd>
            </dl>
        <?php endif; ?>

        <?php if (!empty($listening)): ?>
            <div class="text-muted small text-uppercase fw-bold mt-3 mb-2"><?= __('Listening workflows') ?></div>
            <ul class="list-unstyled small mb-0 d-flex flex-column gap-1">
                <?php foreach ($listening as $listeningId => $listeningName): ?>
                    <li>
                        <a href="<?= h($baseurl . '/workflows/editor/' . (int)$listeningId) ?>"><?= h($listeningName) ?></a>
                        <span class="text-muted">#<?= (int)$listeningId ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
</div>
