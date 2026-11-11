<?php
$deletable  = $deletable ?? [];
$blocked    = $blocked ?? [];
$nbDelete   = count($deletable);
$nbBlocked  = count($blocked);
$canProceed = $nbDelete > 0;

$reasonLabel = function ($reason, $count) {
    if ($reason === 'events') {
        return __('%s event(s) attached', (int)$count);
    }
    return __('%s user(s) attached', (int)$count);
};
?>
<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto" style="max-width: 32rem;">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2">
                <i class="fas fa-trash text-danger me-2"></i>
                <?= $canProceed ? __('Organisation deletion') : __('Deletion not possible') ?>
            </h4>
        </div>

        <div class="card-body">
            <?php if ($canProceed): ?>
                <p class="mb-3">
                    <?= $nbDelete === 1
                        ? __('Are you sure you want to delete the organisation <strong>%s</strong>?', h($deletable[0]['name']))
                        : __('Are you sure you want to delete <strong>%s</strong> organisations?', $nbDelete) ?>
                </p>
            <?php endif; ?>

            <?php if ($nbBlocked > 0): ?>
                <div class="alert alert-warning d-flex mb-3" role="alert">
                    <i class="fas fa-triangle-exclamation me-2 mt-1"></i>
                    <div>
                        <?php if ($nbBlocked === 1): ?>
                            <?= __(
                                'The organisation <strong>%s</strong> cannot be deleted because it still has %s.',
                                h($blocked[0]['name']),
                                h($reasonLabel($blocked[0]['reason'], $blocked[0]['count']))
                            ) ?>
                        <?php else: ?>
                            <?= __('The following organisations cannot be deleted because they still have users or events attached:') ?>
                            <ul class="mb-0 mt-1">
                                <?php foreach ($blocked as $b): ?>
                                    <li>
                                        <strong><?= h($b['name']) ?></strong>
                                        <span class="text-body-secondary">
                                            (<?= h($reasonLabel($b['reason'], $b['count'])) ?>)
                                        </span>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                        <?php if ($canProceed): ?>
                            <div class="mt-2"><?= __('They will be skipped.') ?></div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>

            <?php
                echo $this->Form->create('Organisation', [
                    'id' => 'PromptForm',
                    'url' => $baseurl . '/admin/organisations/deleteSelection',
                    'class' => 'm-0'
                ]);
                echo $this->Form->hidden('id');
            ?>

            <div class="d-flex justify-content-between align-items-center">
                <?php if ($canProceed): ?>
                    <button type="submit" class="btn btn-danger">
                        <?= __('Yes'); ?>
                    </button>
                    <button
                        type="button"
                        class="btn btn-outline-secondary"
                        onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                        <?= __('No'); ?>
                    </button>
                <?php else: ?>
                    <button
                        type="button"
                        class="btn btn-outline-secondary ms-auto"
                        onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                        <?= __('Close'); ?>
                    </button>
                <?php endif; ?>
            </div>

            <?= $this->Form->end(); ?>
        </div>
    </div>
</div>
