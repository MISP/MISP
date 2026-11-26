<?php
$blueprint = $data['WorkflowBlueprint'] ?? [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

// The default blueprints open their description with the trigger they are
// written for, as "[trigger-id]" on the first line.
$description = trim(str_replace("\r", '', (string)($blueprint['description'] ?? '')));
$trigger = null;
if (preg_match('/^\[([a-z0-9_-]+)\]\s*/i', $description, $match)) {
    $trigger = $match[1];
    $description = trim(substr($description, strlen($match[0])));
}
$isDefault = !empty($blueprint['default']);
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <i class="fas fa-diagram-project text-primary me-1"></i><?= __('Workflow blueprint') ?>
            </div>
            <?php if ($description !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($description), false) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div class="row row-cols-1 row-cols-sm-2 g-2">
            <div class="col">
                <div class="d-flex align-items-center gap-2 min-w-0<?= $isDefault ? '' : ' opacity-75' ?>">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $isDefault ? 'bg-primary-subtle text-primary-emphasis' : 'bg-body-secondary text-body-secondary' ?>"
                          style="<?= $tileStyle ?>"><i class="fas fa-box"></i></span>
                    <div class="min-w-0">
                        <div class="fw-semibold lh-sm"><?= $isDefault ? __('Default') : __('Custom') ?></div>
                        <div class="small text-body-secondary text-truncate">
                            <?= $isDefault ? __('Shipped with MISP') : __('Created on this instance') ?>
                        </div>
                    </div>
                </div>
            </div>
            <?php if ($trigger !== null): ?>
                <div class="col">
                    <a class="d-flex align-items-center gap-2 min-w-0 text-decoration-none link-body-emphasis"
                       href="<?= h($baseurl . '/workflows/moduleView/' . $trigger) ?>" title="<?= h(__('Open the trigger')) ?>">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 bg-success-subtle text-success-emphasis"
                              style="<?= $tileStyle ?>"><i class="fas fa-flag"></i></span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm text-truncate font-monospace"><?= h($trigger) ?></div>
                            <div class="small text-body-secondary"><?= __('Written for this trigger') ?></div>
                        </div>
                    </a>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>
